import numpy as np
import tensorflow as tf
import tensorflow.keras as keras

# Adapted from: https://stanford.edu/~shervine/blog/keras-how-to-generate-data-on-the-fly

class DataGenerator(keras.utils.Sequence):
    'Generates data for Tensorflow data pipeline'
    def __init__(self, data_df, batch_size=32, dim=(28, 28, 1), n_channels=1, n_classes=10, shuffle=True):
        '''
        :param data_df: Assumes this dataframe has a column for 'label'
        :param batch_size:
        :param dim:
        :param n_channels:
        :param n_classes:
        :param shuffle:
        '''
        # Initialization
        data_df.reset_index(inplace=True)
        self.dim = dim
        self.batch_size = batch_size
        self.data_df = data_df
        self.list_IDs = data_df.index.values.tolist()
        self.n_channels = n_channels
        self.n_classes = n_classes
        self.shuffle = shuffle
        self.on_epoch_end()

    def __len__(self):
        'Denotes the number of batches per epoch'
        return int(np.floor(len(self.list_IDs) / self.batch_size))

    def __getitem__(self, index):
        'Generate one batch of data'
        # Generate indexes of the batch
        indexes = self.indexes[index*self.batch_size:(index+1)*self.batch_size]

        # Find list of IDs
        list_IDs_temp = [self.list_IDs[k] for k in indexes]

        # Generate data
        X, y = self.__data_generation(list_IDs_temp)

        return X, y

    def on_epoch_end(self):
        '''
        At the end of each epoch, this function prepares the list of data point indexes.
        :return: list of indexes for each epoch
        '''
        self.indexes = np.arange(len(self.list_IDs))
        if self.shuffle == True:
            np.random.shuffle(self.indexes)

    def __data_generation(self, list_IDs_temp):
        '''
        Given a list of IDs for this batch, prepares the data and returns this batch of data.
        :param list_IDs_temp: list of IDs associated with data points in this batch
        :return: batch of prepared data
        '''
        'Generates data containing batch_size samples' # X : (n_samples, *dim, n_channels)
        X = np.empty((self.batch_size, *self.dim, self.n_channels))
        y = np.zeros((self.batch_size), dtype=int)

        batch_counter = 0
        for idx in list_IDs_temp:
            try:
                y[batch_counter] = self.data_df.iloc[idx]['label']
            except:
                print("fail")
            filename = self.data_df.iloc[idx]['data_reference']
            size = self.dim[0] * self.dim[1]
            with open(filename, 'rb') as f:
                buffer = f.read(size)
            datapoint = np.frombuffer(buffer, np.uint8)

            # in case the shapes are not right, we pad with zero's
            np_array_padded = np.zeros(size, dtype=np.uint8)
            np_array_padded[:datapoint.shape[0]] = datapoint
            datapoint = np_array_padded / 255.0
            datapoint = datapoint.reshape(self.dim[0], self.dim[1], 1)

            X[batch_counter,] = datapoint
            batch_counter += 1

        return X, y
