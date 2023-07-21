import json

import pandas as pd
import plotly
import plotly.graph_objs as go
from cybernews.cybernews import CyberNews
from flask import Flask, request
from flask import redirect
from flask import render_template

import algorithm.config as config
import algorithm.data_processing as dp
import algorithm.machine_learning as ml

app = Flask(__name__)

train_model_file_location = 'dataset/updated_cve_2023_07_09.csv'
analysis_file_location = 'dataset/vulnerabilities.csv'

MAPPING, THRESHOLD, VARIABLES_OF_INTEREST = config.MAPPING, config.THRESHOLD, config.VARIABLES_OF_INTEREST

df = dp.load_data(train_model_file_location)
df_analysis = dp.load_data(analysis_file_location)

filtered_df = df.dropna(subset=VARIABLES_OF_INTEREST, how='all')

# Store analysis results globally
global analysis_results
analysis_results = None


@app.route('/')
def index():
    return redirect("/analytics", code=302)


@app.route('/resources')
def resources():
    return render_template('resources.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/news')
def news():
    return render_template('news.html')


@app.route('/news/general')
def general_news():
    # Fetch general news articles from CyberNews
    cybernews = CyberNews()
    news = cybernews.get_news("general")

    return render_template('general_news.html', news=news)


@app.route('/news/data-breach')
def data_breach_news():
    # Fetch data breach news articles from CyberNews
    cybernews = CyberNews()
    news = cybernews.get_news("dataBreach")

    return render_template('data_breach_news.html', news=news)


@app.route('/news/cyber-attack')
def cyber_attack_news():
    # Fetch cyber attack news articles from CyberNews
    cybernews = CyberNews()
    news = cybernews.get_news("cyberAttack")

    return render_template('cyber_attack_news.html', news=news)


# Add more routes for other news categories


@app.route('/analytics')
def analytics():
    global analysis_results

    # Perform analysis if results are not available
    if analysis_results is None:
        vulnerability_dict = dp.store_vulnerabilities_in_dict(filtered_df, 'vulnerability', True)
        analysis_results = vulnerability_dict

    # Create a list of line traces
    traces = []
    for vulnerability, df in analysis_results.items():
        trace = go.Scatter(
            x=df['cve.published'],
            y=df['Number_of_Vulnerabilities'],
            mode='lines',
            name=vulnerability
        )
        traces.append(trace)

    fig = dp.analyze_attack_types_by_vendor(df_analysis)
    graphJSON2 = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)


    # Convert to JSON
    graphJSON = json.dumps(traces, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('analytics.html', graphJSON=graphJSON , graphJSON2=graphJSON2)


@app.route('/predict')
def plot():
    predict_scores =  None
    return render_template('predict.html',predict_scores=predict_scores)


@app.route('/submit', methods=['POST'])
def submit():

    user_input_basedScore = float(request.form.get('user_input_basedScore'))
    user_input_exploitabilityScore = float(request.form.get('user_input_exploitabilityScore'))
    user_input_Mixed_impactScore = float(request.form.get('user_input_Mixed_impactScore'))
    user_input_obtain_privilege = int(request.form.get('user_input_obtain_privilege'))
    user_input_userinteraction = int(request.form.get('user_input_userinteraction'))

    # Train the model and get predicted probabilities
    vulnerability_model = ml.VulnerabilityModel(df)
    y_test, y_pred_proba, X_test = vulnerability_model.train_model(3)

    accuracy, confusion, precision, recall, f1, auc_roc = vulnerability_model.evaluate_model(X_test, y_test)

    # Print the metrics or send them to the front-end
    print("Accuracy: ", accuracy)
    print("Confusion Matrix: ", confusion)
    print("Precision: ", precision)
    print("Recall: ", recall)
    print("F1 Score: ", f1)
    print("AUC-ROC: ", auc_roc)

    # Create a histogram of the predicted probabilities
    trace0 = go.Histogram(
        x=y_pred_proba[y_test == 0],
        opacity=0.75,
        name='True Negatives'
    )

    trace1 = go.Histogram(
        x=y_pred_proba[y_test == 1],
        opacity=0.75,
        name='True Positives'
    )

    data = [trace0, trace1]

    new_data = pd.DataFrame({
        'Mixed_basedScore': [user_input_basedScore],
        'Mixed_exploitabilityScore': [user_input_exploitabilityScore],
        'Mixed_impactScore': [user_input_Mixed_impactScore],
        'Mixed_obtainPrivilege': [user_input_obtain_privilege],
        'Mixed_userInteractionRequired': [user_input_userinteraction]
    })

    predict_scores = vulnerability_model.predict(new_data)
    predict_scores = (predict_scores[predict_scores == 1].shape[0] / predict_scores.shape[0]) * 100

    accuracy = round(accuracy * 100, 2)

    # Convert to JSON
    graphJSON = json.dumps(data, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('predict.html', graphJSON=graphJSON ,predict_scores=predict_scores, accuracy=accuracy)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
