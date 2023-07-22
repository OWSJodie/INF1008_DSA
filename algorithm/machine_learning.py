import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score
from os import path


class VulnerabilityModel:
    def __init__(self, data):

        """
        Initialize the VulnerabilityModel instance.

        Parameters:
        - data (pandas.DataFrame): The DataFrame containing the vulnerability data.
        """


        self.data = data
        self.model = None

    def train_model(self, threshold):

        """
        Train the logistic regression model to predict vulnerability severity.

        Parameters:
        - threshold (float): The threshold for determining high or low severity.

        Returns:
        - y_test (pandas.Series): The actual target values for the test set.
        - y_pred_proba (numpy.ndarray): The predicted probabilities for the test set.
        - X_test (pandas.DataFrame): The test features used for prediction.
        """

        X_test, y_test = None, None  # Initialize X_test and y_test

        # Define the outcome variable
        features = ['Mixed_basedScore', 'Mixed_exploitabilityScore', 'Mixed_impactScore', "Mixed_obtainPrivilege",
                    "Mixed_userInteractionRequired"]
        X = self.data[features]
        y = pd.to_numeric(self.data['Mixed_baseSeverity'], errors='coerce') >= threshold
        severity_counts = self.data['Mixed_baseSeverity'].value_counts()
        print("this is severity_counts: ")
        print(severity_counts)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model = LogisticRegression()
        self.model.fit(X_train, y_train)

        # Save the trained model to a file
        joblib.dump(self.model, 'model.pkl')

        # Get predicted probabilities
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]

        return y_test, y_pred_proba, X_test

    def predict(self, X):

        """
        Make predictions using the trained model.

        Parameters:
        - X (pandas.DataFrame): The features for making predictions.

        Returns:
        - y_pred (numpy.ndarray): The predicted target values (binary: 0 or 1).
        """

        # Load the trained model from a file if it's not loaded
        if self.model is None:
            self.model = joblib.load('model.pkl')

        # Make predictions
        y_pred = self.model.predict(X)
        return y_pred

    def evaluate_model(self, X_test, y_test):

        """
        Evaluate the performance of the trained model.

        Parameters:
        - X_test (pandas.DataFrame): The test features used for evaluation.
        - y_test (pandas.Series): The actual target values for the test set.

        Returns:
        - accuracy (float): The accuracy of the model.
        - confusion (numpy.ndarray): The confusion matrix.
        - precision (float): The precision score.
        - recall (float): The recall score.
        - f1 (float): The F1 score.
        - auc_roc (float): The area under the ROC curve.
        """

        # Make sure the model is loaded
        if self.model is None:
            self.model = joblib.load('model.pkl')

        # Make predictions
        y_pred = self.model.predict(X_test)

        # Compute metrics
        accuracy = accuracy_score(y_test, y_pred)
        confusion = confusion_matrix(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        # Compute AUC-ROC
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        auc_roc = roc_auc_score(y_test, y_pred_proba)

        # Return all metrics
        return accuracy, confusion, precision, recall, f1, auc_roc