import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score
from os import path

class VulnerabilityModel:
    def __init__(self, data):
        self.data = data
        self.model = None

    def train_model(self, threshold):
        X_test, y_test = None, None  # Initialize X_test and y_test

        # Define the outcome variable
        self.data['Attack'] = (self.data['Mixed_baseSeverity'] > threshold).astype(int)
        features = ['Mixed_basedScore', 'Mixed_exploitabilityScore', 'Mixed_impactScore']
        X = self.data[features]
        y = self.data['Attack']

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model = LogisticRegression()
        self.model.fit(X_train, y_train)

        # Save the trained model to a file
        joblib.dump(self.model, 'model.pkl')

        # Get predicted probabilities
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]




        return y_test, y_pred_proba, X_test

    def predict(self, X):
        # Load the trained model from a file if it's not loaded
        if self.model is None:
            self.model = joblib.load('model.pkl')

        # Make predictions
        y_pred = self.model.predict(X)
        return y_pred

    def evaluate_model(self, X_test, y_test):
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
