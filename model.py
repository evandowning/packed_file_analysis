from __future__ import absolute_import, division, print_function, unicode_literals
import argparse
import tensorflow as tf
from tensorflow.keras import datasets, layers, models
import lib.utils as utils
from lib.file_data_pipeline import DataGenerator
from lib.confusion_matrix import plot_confusion_matrix_from_data
import pandas as pd
import numpy as np
import os
import time
from datetime import datetime

EPOCHS = 20
BATCH_SIZE = 32
NAME = "PackerIdentifier-medium-{}_epochs_{}_batchsize_{}".format(EPOCHS, BATCH_SIZE, datetime.now().isoformat().replace(':',''))
CLASSES = ['not_packed', 'mpress', 'aspack', 'andpakk2', 'upx']
CLASS_TO_IDX = {CLASSES[i]: i for i in range(len(CLASSES))}


def translate_class(label_or_idx):
    try:
        return CLASSES[label_or_idx]
    except:
        return CLASS_TO_IDX.get(label_or_idx, None)

def prepare_dataset(filepath, savefile=None, overwrite=True, max_num_per_label=None):
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
        # Excluding '.' in filenames because my dataset has no extensions or anything in the file names.  Filters out things like .csv or .gz files.
        if os.path.isfile(filename) and '.' not in filename:
            for label in CLASSES:
                # ensure one of the labels is present
                if label in filename:
                    sample_label = translate_class(label)
                    entry = {'label' : sample_label, 'data_reference' : filename}
                    labeled_files.append(entry)

    df = pd.DataFrame(labeled_files)
    min_cnt_per_label = int(df.label.value_counts().min())
    if max_num_per_label is not None:
        min_cnt_per_label = max_num_per_label

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

def build_model(shape=(28, 28, 1), num_classes=10):

    model = models.Sequential()
    model.add(layers.Conv2D(64, (3, 3), strides=2, activation='relu', input_shape=shape))
    model.add(layers.MaxPooling2D((2, 2)))
    model.add(layers.Conv2D(32, (3, 3), strides=2, activation='relu'))
    model.add(layers.MaxPooling2D((2, 2)))
    model.add(layers.Conv2D(16, (3, 3), strides=2, activation='relu'))
    model.add(layers.Flatten())
    model.add(layers.Dropout(0.3))
    model.add(layers.Dense(64, activation='relu'))
    model.add(layers.Dense(num_classes, activation='softmax'))

    model.compile(optimizer='adam',
                  loss='sparse_categorical_crossentropy',
                  metrics=['accuracy'])

    return model

def fit_model(model, training_generator, validation_generator):
    # CHECKPOINTS while Training
    checkpoint_path = "checkpoints/cp-{}-{}.ckpt".format(NAME, '{epoch:04d}')
    checkpoint_dir = os.path.dirname(checkpoint_path)

    # Create checkpoint callback
    checkpoint_callback = tf.keras.callbacks.ModelCheckpoint(checkpoint_path,
                                                     save_weights_only=True,
                                                     save_best_only=False,
                                                     verbose=1,
                                                     save_freq='epoch')

    # Tensorboard Callback
    tensorboard_callback = tf.keras.callbacks.TensorBoard(log_dir='logs/{}'.format(NAME))

    model.fit_generator(training_generator,
                        validation_data=validation_generator,
                        verbose=1,
                        epochs=EPOCHS,
                        use_multiprocessing=True,
                        workers=16,
                        callbacks=[checkpoint_callback, tensorboard_callback])

    return model

def train(filepath):
    files_df = prepare_dataset(filepath, savefile=None, overwrite=False)
    train_idx = np.random.rand(len(files_df)) < 0.8
    df_train_files = files_df[train_idx].copy()
    df_test_files = files_df[~train_idx].copy()

    data_pipeline_test = DataGenerator(df_test_files, batch_size=BATCH_SIZE, dim=(512, 512), n_channels=1, n_classes=len(CLASSES), shuffle=True)
    data_pipeline_train = DataGenerator(df_train_files, batch_size=BATCH_SIZE, dim=(512, 512), n_channels=1, n_classes=len(CLASSES), shuffle=True)

    model = build_model(shape=(512, 512, 1), num_classes=len(CLASSES))
    model.summary()

    start_time = time.time()
    fit_model(model, data_pipeline_train, data_pipeline_test)
    print("\nTotal Train Time: %s minutes ---\n" % ((time.time() - start_time) / 60.0))

    # Save current model
    saved_model_file = './saved_models/{}_model.h5'.format(datetime.now().isoformat().replace(':',''))
    model.save(saved_model_file)

    # Use train model with test data to generate confusion matrix
    df_eval_files = df_test_files[0 : BATCH_SIZE*int(len(df_test_files) / BATCH_SIZE)].copy()
    data_pipeline_eval = DataGenerator(df_eval_files, batch_size=BATCH_SIZE, dim=(512, 512), n_channels=1, n_classes=len(CLASSES), shuffle=False)
    results = model.predict_generator(data_pipeline_eval)

    predictions = results.argmax(axis=1)
    actual = list(df_eval_files.label.values)

    if len(CLASSES) > 10:
        fig_size = [14,14]
    plot_confusion_matrix_from_data(actual, predictions, CLASSES, filepath='./{}_confusion.png'.format(datetime.now().isoformat().replace(':','')))


def predict(filepath, tag):
    if tag is None:
        tag = ''
    all_files = utils.get_files('./saved_models')
    model_filepath = ''
    for filename in all_files:
        if tag in filename and filename.endswith('.h5'):
            if model_filepath != '':
                print("Found multiple possible models to predict with, going to use this one: {}".format(model_filepath))
            else:
                model_filepath = filename
                print('Found model {}'.format(model_filepath))

    restored_model = models.load_model(model_filepath)

    files_to_predict = utils.get_files(filepath)
    df_predict_files = pd.DataFrame(files_to_predict, columns=['data_reference'])
    df_predict_files['label'] = -1

    data_pipeline_eval = DataGenerator(df_predict_files, batch_size=1, dim=(512, 512), n_channels=1, n_classes=len(CLASSES), shuffle=False)
    results = restored_model.predict_generator(data_pipeline_eval)
    predictions = results.argmax(axis=1)

    prediction_results = []
    for idx in range(len(predictions)):
        entry = {}
        entry['filename'] = df_predict_files.iloc[idx]['data_reference']
        entry['predicted_label_index'] = predictions[idx]
        entry['predicted_label'] = translate_class(predictions[idx])
        prediction_results.append(entry)

    df_predictions = pd.DataFrame(prediction_results)
    print(df_predictions)

    return df_predictions

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parses metadata from files and stores them in log files.')
    parser.add_argument('-d', '--directory', help='Directory containing files to analyze (will recurse to sub directories).')
    parser.add_argument('-t', '--tag', help='Directory containing files to analyze (will recurse to sub directories).')
    parser.add_argument('-p', '--predict', action="store_true")
    args = parser.parse_args()

    tag = None
    if args.tag:
        tag = args.tag

    if args.directory:
        if os.path.exists(args.directory):
            filepath = args.directory
        else:
            print("\nDirectory provided did not exist.\n")
            parser.print_help()
            exit()
    else:
        print("\nMust provide a directory of files to process.\n")
        parser.print_help()
        exit()

    if not args.predict:
        train(filepath, tag)
    else:
        predict(filepath, tag)
