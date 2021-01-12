import os
import sys
import pickle
import re
import numpy
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

class MachineLearningDetection():

    def __init__(self) -> None:
        self

    def get_string_features(self, path,hasher):
        # extract strings from binary file using regular expressions
        chars = r" -~"
        min_length = 5
        string_regexp = '[%s]{%d,}' % (chars, min_length)
        data = os.popen(f"{path}").read()
        #data = file_object.read()
        pattern = re.compile(string_regexp)
        strings = pattern.findall(data)
        string_features = {}
        for string in strings:
            string_features[string] = 1

        # hash the features using the hashing trick
        hashed_features = hasher.transform([string_features])

        # do some data munging to get the feature array
        hashed_features = hashed_features.todense()
        hashed_features = numpy.asarray(hashed_features)
        hashed_features = hashed_features[0]

        # return hashed string features
        print ("Extracted {0} strings from {1}".format(len(string_features),path))
        return hashed_features

    def scan_file(self, path):
        # scan a file to determine if it is malicious or benign
        if not os.path.exists("saved_detector.pkl"):
            print ("It appears you haven't trained a detector yet!  Do this before scanning files.")
            sys.exit(1)
        with open("saved_detector.pkl") as saved_detector:
            classifier, hasher = pickle.load(saved_detector)
        features = self.get_string_features(path,hasher)
        result_proba = classifier.predict_proba([features])[:,1]
        # if the user specifies malware_paths and benignware_paths, train a detector
        if result_proba > 0.5:
            print (f"It appears this file is malicious!{result_proba}")
        else:
            print (f"It appears this file is benign{result_proba}")

    def train_detector(self, benign_path,malicious_path,hasher):
        # train the detector on the specified training data
        def get_training_paths(directory):
            targets = []
            for path in os.listdir(directory):
                targets.append(os.path.join(directory,path))
            return targets
        malicious_paths = get_training_paths(malicious_path)
        benign_paths = get_training_paths(benign_path)
        X = [self.get_string_features(path,hasher) for path in malicious_paths + benign_paths]
        y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
        classifier = RandomForestClassifier(64)
        classifier.fit(X,y)
        pickle.dump((classifier,hasher),open("saved_detector.pkl","w+"))

    def cv_evaluate(self, X,y,hasher):
        # use cross-validation to evaluate our model
        import random
        from sklearn import metrics
        from matplotlib import pyplot
        from sklearn.model_selection import KFold
        X, y = numpy.array(X), numpy.array(y)
        fold_counter = 0
        for train, test in KFold(len(X),2,shuffle=True):
            training_X, training_y = X[train], y[train]
            test_X, test_y = X[test], y[test]
            classifier = RandomForestClassifier(64)
            classifier.fit(training_X,training_y)
            scores = classifier.predict_proba(test_X)[:,-1]
            fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
            #pyplot.semilogx(fpr,tpr,label="Fold number {0}".format(fold_counter))
            pyplot.semilogx(fpr,tpr,label="ROC curve".format(fold_counter))
            fold_counter += 1
            break
        pyplot.xlabel("detector false positive rate")
        pyplot.ylabel("detector true positive rate")
        pyplot.title("Detector ROC curve")
        #pyplot.title("detector cross-validation ROC curves")
        pyplot.legend()
        pyplot.grid()
        pyplot.show()

    def get_training_data(self, benign_path,malicious_path,hasher):
        def get_training_paths(directory):
            targets = []
            for path in os.listdir(directory):
                targets.append(os.path.join(directory,path))
            return targets
        malicious_paths = get_training_paths(malicious_path)
        benign_paths = get_training_paths(benign_path)
        X = [self.get_string_features(path,hasher) for path in malicious_paths + benign_paths]
        y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
        return X, y
