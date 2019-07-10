import lib.utils as utils
import pefile
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
import os
import matplotlib.pyplot as plt

classes = ['not_packed', 'mpress', 'aspack', 'andpakk2', 'upx']
class_to_idx = {classes[i]: i for i in range(len(classes))}
num_bytes = 1024

def translate_class(label_or_idx):
    try:
        return classes[label_or_idx]
    except:
        return class_to_idx.get(label_or_idx, None)

def extract_data(filepath):
    all_files = utils.get_files(filepath)

    labeled_files = []
    for filename in all_files:
        if '.gz' in filename:
            for label in classes:
                # ensure one of the labels is present
                if label in filename:
                    sample_label = translate_class(label)
                    entry = {'label' : sample_label, 'filename' : filename}
                    labeled_files.append(entry)

    df = pd.DataFrame(labeled_files)
    min_cnt_per_label = int(df.label.value_counts().min())
    # Fix at 10 for now
    min_cnt_per_label = 100
    df_files_to_use = pd.DataFrame()
    for label_idx in range(len(classes)):
        df_tmp = df[df['label']==label_idx].head(min_cnt_per_label)
        df_files_to_use = pd.concat([df_files_to_use, df_tmp])
    print("Total data length: {}".format(len(df_files_to_use)))
    print("\nBreakdown:")
    print(df_files_to_use.label.value_counts())

    return df_files_to_use

def get_raw_bytes(filename, size=1024):
    try:
        buffer = utils.decompress_file(filename, in_memory=True)
        pe = pefile.PE(data=buffer)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        np_array = np.frombuffer(pe.get_data(ep, length=size), np.uint8)
        # Pad the array if needed
        if np_array.shape[0] != size:
            np_array_padded =  np.zeros(size, dtype=np.uint8)
            np_array_padded[:np_array.shape[0]] = np_array
            return np_array_padded
        return np_array
    except:
        return None

def prepare_raw_bytes_for_model(files_df):
    labels = []
    data = []
    for idx in range(len(files_df)):
        label = files_df.iloc[idx]['label']
        filename = files_df.iloc[idx]['filename']
        sample_bytes = get_raw_bytes(filename, num_bytes)
        if sample_bytes is not None:
            data.append(sample_bytes)
            labels.append(label)
    return np.vstack(data), np.array(labels)

def train_test_split(data, labels):
    indicies = np.random.permutation(data.shape[0])
    eighty_pct_idx = round(data.shape[0]*.8)
    train_idx, test_idx = indicies[:eighty_pct_idx], indicies[eighty_pct_idx:]
    train_data, test_data = data[train_idx,:], data[test_idx,:]
    train_labels, test_labels = labels[train_idx,], labels[test_idx,]
    return train_data, train_labels, test_data, test_labels


def build_model(num_features, num_labels):
  model = keras.Sequential([
    keras.layers.Dense(128, activation=tf.nn.relu, input_shape=(num_features,)),
    keras.layers.Dense(128, activation=tf.nn.relu),
    keras.layers.Dropout(0.2),
    keras.layers.Dense(num_labels, activation='softmax')
  ])

  model.compile(optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy'])
  return model


def fit_model(model, train_data, train_labels, test_data, test_labels, checkpoint_path='./checkpoints'):
    # CHECKPOINTS while Training
    checkpoint_path = "training_dga/cp-{epoch:04d}.ckpt"
    checkpoint_dir = os.path.dirname(checkpoint_path)

    # Create checkpoint callback
    cp_callback = tf.keras.callbacks.ModelCheckpoint(checkpoint_path,
                                                     save_weights_only=True,
                                                     verbose=1, period=5)

    # Display training progress by printing a single dot for each completed epoch
    class PrintDot(keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs):
            if epoch % 100 == 0: print('')
            print('.', end='')

    EPOCHS = 100

    # Stop early if loss is not improving
    early_stop = keras.callbacks.EarlyStopping(monitor='val_loss', patience=10)

    history = model.fit(
        train_data, train_labels,
        epochs=EPOCHS, validation_data=(test_data, test_labels), verbose=0,
        callbacks=[cp_callback, early_stop])

    return history, model

def plot_history(history, name, key):
    plt.figure(figsize=(16,10))
    val = plt.plot(history.epoch, history.history['val_'+key],
                   '--', label=name.title()+' Test')
    plt.plot(history.epoch, history.history[key], color=val[0].get_color(),
              label=name.title()+' Train')

    plt.xlabel('Epochs')
    plt.ylabel(key.replace('_',' ').title())
    plt.legend()
    plt.savefig('100_accuracy_plot.png')


if __name__ == "__main__":
    files_df = extract_data("/media/test/malware/packer_analysis")
    data, labels = prepare_raw_bytes_for_model(files_df)
    train_data, train_labels, test_data, test_labels = train_test_split(data, labels)

    model = build_model(num_bytes, len(classes))
    model.summary()

    history, model = fit_model(model, train_data, train_labels, test_data, test_labels, checkpoint_path='./checkpoints')

    plot_history(history, 'Simple Example', 'accuracy')

    loss, acc = model.evaluate(test_data, test_labels)
    print("Trained model, test accuracy: {:5.2f}%".format(100*acc))

    model2 = build_model(num_bytes, len(classes))
    loss, acc = model2.evaluate(test_data, test_labels)
    print("Untrained model, test accuracy: {:5.2f}%".format(100*acc))
