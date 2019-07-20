import lib.utils as utils
import pefile
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
import os
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
import argparse
from datetime import datetime

NAME = "PackerIdentifier-{}".format(datetime.now().isoformat().replace(':',''))
CLASSES = ['not_packed', 'mpress', 'aspack', 'andpakk2', 'upx']
CLASS_TO_IDX = {CLASSES[i]: i for i in range(len(CLASSES))}
NUM_BYTES = 1024
BATCH_SIZE = 32

# XLA_FLAGS=--xla_hlo_profile python build_model.py -d "/home/test/vm_shared/packed_exes/test_data_packed" -t 64n

def translate_class(label_or_idx):
    try:
        return CLASSES[label_or_idx]
    except:
        return CLASS_TO_IDX.get(label_or_idx, None)

def extract_data(filepath, savefile=None, overwrite=True):
    # Save file provided and we are just loading it
    if savefile is not None:
        if not overwrite:
            if os.path.exists(savefile):
                df_files_to_use = pd.read_csv(savefile)
                if len(df_files_to_use) > 1:
                    return df_files_to_use

    all_files = utils.get_files(filepath)

    labeled_files = []
    for filename in all_files:
        if '.gz' in filename:
            for label in CLASSES:
                # ensure one of the labels is present
                if label in filename:
                    sample_label = translate_class(label)
                    entry = {'label' : sample_label, 'filename' : filename}
                    labeled_files.append(entry)

    df = pd.DataFrame(labeled_files)
    min_cnt_per_label = int(df.label.value_counts().min())
    min_cnt_per_label = 50

    df_files_to_use = pd.DataFrame()
    for label_idx in range(len(CLASSES)):
        df_tmp = df[df['label']==label_idx].head(min_cnt_per_label)
        df_files_to_use = pd.concat([df_files_to_use, df_tmp])
    print("Total data length: {}".format(len(df_files_to_use)))
    print("\nBreakdown:")
    print(df_files_to_use.label.value_counts())

    if savefile is not None:
        df_files_to_use.to_csv(savefile, index=False, header=True, encoding='utf-8')

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
        sample_bytes = get_raw_bytes(filename, NUM_BYTES)
        if sample_bytes is not None:
            data.append(sample_bytes)
            labels.append(label)
    return np.vstack(data), np.array(labels)

def train_test_split_tf(data, labels):
    indicies = np.random.permutation(data.shape[0])
    eighty_pct_idx = round(data.shape[0]*.8)
    train_idx, test_idx = indicies[:eighty_pct_idx], indicies[eighty_pct_idx:]
    train_data, test_data = data[train_idx,:], data[test_idx,:]
    train_labels, test_labels = labels[train_idx,], labels[test_idx,]
    return train_data, train_labels, test_data, test_labels


def build_model(num_features, num_labels):
    model = keras.Sequential([
    keras.layers.Dense(64, activation=tf.nn.relu, input_shape=(num_features,)),
    keras.layers.Dense(64, activation=tf.nn.relu),
    keras.layers.Dropout(0.2),
    keras.layers.Dense(num_labels, activation='softmax')
    ])

    model.compile(optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy'])
    return model

def build_models(config):
    dense_layers = config.get('dense_layers', 1)
    layer_sizes = config.get('layer_sizes', 32)
    conv_layers = config.get('conv_layers', 1)
    models = []

    config = []
    for dense_layer in dense_layers:
        for layer_size in layer_sizes:
            for conv_layer in conv_layers:
                print("hi")

    #
    #
    # models = []
    # for entry in config:
    #     model = keras.Sequential([
    #     keras.layers.Dense(64, activation=tf.nn.relu, input_shape=(num_features,)),
    #     keras.layers.Dense(64, activation=tf.nn.relu),
    #     keras.layers.Dropout(0.2),
    #     keras.layers.Dense(num_labels, activation='softmax')
    #     ])
    #
    #     model.compile(optimizer='adam',
    #                 loss='sparse_categorical_crossentropy',
    #                 metrics=['accuracy'])
    return models


def fit_model(model, train_data, test_data):
    # CHECKPOINTS while Training
    checkpoint_path = "checkpoints/cp-{}-{}.ckpt".format(NAME, '{epoch:04d}')
    checkpoint_dir = os.path.dirname(checkpoint_path)

    # Create checkpoint callback
    checkpoint_callback = tf.keras.callbacks.ModelCheckpoint(checkpoint_path,
                                                     save_weights_only=True,
                                                     save_best_only=True,
                                                     verbose=1,
                                                     save_freq='epoch')

    # Tensorboard Callback
    tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir='logs/{}'.format(NAME))

    # Display training progress by printing a single dot for each completed epoch
    class PrintDot(keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs):
            if epoch % 100 == 0: print('')
            print('.', end='')

    EPOCHS = 10

    # Stop early if loss is not improving
    # early_stop = keras.callbacks.EarlyStopping(monitor='val_loss', patience=5)

    # https://www.tensorflow.org/versions/r2.0/api_docs/python/tf/keras/Model#fit_generator
    history = model.fit_generator(generate_file_byte_input(train_data, BATCH_SIZE),
                                  epochs=EPOCHS,
                                  steps_per_epoch=len(train_data),
                                  validation_steps=len(test_data),
                                  validation_data=generate_file_byte_input(test_data),
                                  verbose=0,
                                  use_multiprocessing=True,
                                  workers=10,
                                  max_queue_size=64,
                                  callbacks=[checkpoint_callback, tensorboard_callback])

    return history, model

def plot_history(history, name, key, tag):
    plt.figure(figsize=(16,10))
    val = plt.plot(history.epoch, history.history['val_'+key],
                   '--', label=name.title()+' Test')
    plt.plot(history.epoch, history.history[key], color=val[0].get_color(),
              label=name.title()+' Train')

    plt.xlabel('Epochs')
    plt.ylabel(key.replace('_',' ').title())
    plt.legend()
    plt.savefig('{}_data_pipeline_accuracy_plot_{}.png'.format(tag, datetime.now().isoformat().replace(':','')))


def generate_file_byte_input(files_df, batch_size=32):
    '''
    Given a dataframe of paths to executables, produces a batch of training data and labels that can be fed into
    tensorflow for model training from the raw bytes in those executables.

    This function can be used like so:
    mygenerator = generate_file_byte_input(files_df, 8)
    batch1 = next(mygenerator)
    batch2 = next(mygenerator)
            ...

    :param files_df: dataframe with filenames, where the filename contains one of the valid labels defined in the global
    variable CLASSES
    :param batch_size: number of data points to return
    :return: yeilds a batch as a tuple(np_array_X, np_array_labels)
    '''
    while 1:
        # Shuffle data before looping
        files_df = files_df.sample(frac=1).reset_index(drop=True)

        cur_batch = 0
        num_batches = int(len(files_df) / batch_size)
        batch_data = []
        batch_labels = []

        for batch_no in range(num_batches):

            for i in range(batch_size):
                idx = cur_batch * batch_size + i

                filename = files_df.iloc[idx]['filename']
                sample_bytes = get_raw_bytes(filename, NUM_BYTES)
                sample_label = None
                for label in CLASSES:
                    # ensure one of the labels is present
                    if label in filename:
                        sample_label = translate_class(label)
                if sample_bytes is not None and sample_label is not None:
                    batch_data.append(sample_bytes)
                    batch_labels.append(sample_label)

                if len(batch_data) == batch_size:
                    np_batch_data = np.array(batch_data)
                    np_batch_labels = np.array(batch_labels)
                    yield (np_batch_data, np_batch_labels)
                    batch_data = []
                    batch_labels = []

            cur_batch += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses metadata from files and stores them in log files.')
    parser.add_argument('-d', '--directory', help='Directory containing files to analyze (will recurse to sub directories).')
    parser.add_argument('-t', '--tag', help='Directory containing files to analyze (will recurse to sub directories).')
    args = parser.parse_args()

    if not args.directory or not args.tag:
        print("\nMust supply a directory and a tag for this model run.\n")
        parser.print_help()
        exit()

    savefile = os.path.join(args.directory, 'file_index.csv')
    files_df = extract_data(args.directory, savefile=savefile, overwrite=True)

    train_idx = np.random.rand(len(files_df)) < 0.8
    train = files_df[train_idx]
    test = files_df[~train_idx]
    num_test_batches = int(len(test) / BATCH_SIZE)

    model = build_model(NUM_BYTES, len(CLASSES))
    model.summary()

    print("\nStarting training with {} training samples and {} test samples".format(train.shape[0], test.shape[0]))

    history, model = fit_model(model, train, test)

    plot_history(history, 'Simple Example', 'accuracy', args.tag)

    loss, acc = model.evaluate_generator(generate_file_byte_input(test), steps=num_test_batches)
    print("Trained model, test accuracy: {:5.2f}%".format(100*acc))

    model2 = build_model(NUM_BYTES, len(CLASSES))
    loss, acc = model2.evaluate_generator(generate_file_byte_input(test), steps=(num_test_batches))
    print("Untrained model, test accuracy: {:5.2f}%".format(100*acc))
