import json
import plotly
import plotly.graph_objs as go
from cybernews.cybernews import CyberNews
from flask import Flask, request, session
from flask import redirect
from flask import render_template
import algorithm.config as config
import algorithm.data_processing as dp
import algorithm.machine_learning as ml

app = Flask(__name__)

file_location = 'dataset/updated_cve_2023_07_09.csv'

MAPPING, THRESHOLD, VARIABLES_OF_INTEREST = config.MAPPING, config.THRESHOLD, config.VARIABLES_OF_INTEREST

df = dp.load_data(file_location)
df = dp.map_words_to_values(df, 'Mixed_baseSeverity', MAPPING)

filtered_df = df[(df[VARIABLES_OF_INTEREST] != 0).dropna().all(axis=1)]

# Train the model
vulnerability_model = ml.VulnerabilityModel(df)
model = vulnerability_model.train_model(THRESHOLD)

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

    # Convert to JSON
    graphJSON = json.dumps(traces, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('analytics.html', graphJSON=graphJSON)


@app.route('/plot')
def plot():
    graphJSON = session.get('graphJSON')

    return render_template('plot.html', graphJSON=graphJSON)


@app.route('/submit', methods=['POST'])
def submit():
    user_input_threshold = request.form.get('user_input_threshold')
    user_input_generate_size = request.form.get('user_input_generate_size')

    threshold = float(user_input_threshold)  # Convert user input to float and use as threshold
    generate_size = int(user_input_generate_size) # Convert user input to integer and use as generate_size

    # Train the model and get predicted probabilities
    vulnerability_model = ml.VulnerabilityModel(df)
    y_test, y_pred_proba, X_test = vulnerability_model.train_model(threshold)

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

    # Generate synthetic data
    new_data = dp.generate_synthetic_data(df, generate_size)

    # Make predictions on the synthetic data
    predictions = vulnerability_model.predict(new_data)

    # Create a histogram of the predicted probabilities for the synthetic data
    trace3 = go.Histogram(
        x=predictions,
        opacity=0.75,
        name='Predictions on synthetic data'
    )

    data.append(trace3)  # Add the new trace to the data

    # Convert to JSON
    graphJSON = json.dumps(data, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('plot.html', graphJSON=graphJSON)



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
