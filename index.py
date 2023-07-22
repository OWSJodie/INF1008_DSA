import json
import os

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
import algorithm.RansomwareAttackByIndustryGraph as RansonwareAttackGraph

import plotly.io as pio

import patoolib

app = Flask(__name__)

analysis_file_location = 'dataset/vulnerabilities.csv'
uncleaned_train_model_file_location = 'dataset/updated_cve_2023_07_19.xlsx'
train_model_file_location = 'dataset/updated_cve_2023_07_19.csv'
archive_path = "dataset/Dataset.rar"

file_paths_to_check = [
    'dataset/vulnerabilities.csv',
    'dataset/Full_FYP_crawled_edit.csv',
    'dataset/Copy_of_Ransomware_Attacks.xlsx',
    'dataset/updated_cve_2023_07_19.xlsx'
    # Add more file paths here as needed
]

for file_path in file_paths_to_check:
    if not os.path.isfile(file_path):
        try:
            # Extract the RAR archive to the destination directory
            patoolib.extract_archive(archive_path, outdir='dataset')
            print(f"RAR file '{file_path}' successfully extracted.")
            print("Converting some file to csv")
            dp.convert_xlsx_to_cleaned_csv(uncleaned_train_model_file_location, train_model_file_location)
        except patoolib.util.PatoolError:
            print(f"RAR file '{file_path}' not found or extraction failed.")

df = dp.load_data(train_model_file_location)
df_analysis = dp.load_data(analysis_file_location)

VARIABLES_OF_INTEREST = config.VARIABLES_OF_INTEREST
filtered_df = df.dropna(subset=VARIABLES_OF_INTEREST, how='all')


@app.route('/')
def index():
    return redirect("/news", code=302)


@app.route('/resources')
def resources():
    # Save the plot as an image file
    image_path = 'static/images/RansonwareAttackGraph.png'
    RansonwareAttackGraph.run().savefig(image_path)

    return render_template('resources.html', image_path=image_path)


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


@app.route('/vendors')
def vendors():
    df_analysis_copy = df_analysis.copy()
    fig = dp.analyze_attack_types_by_vendor(df_analysis_copy)
    df_analysis_copy = df_analysis.copy()
    fig_top_5 = dp.top_5_vulnerability_by_vendor(df_analysis_copy)

    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    graphJSON2 = fig_top_5.to_json()

    return render_template('vendors.html', graphJSON=graphJSON, graphJSON2=graphJSON2)


@app.route('/vulnerabilities')
def vulnerabilities():
    df_analysis_copy = df_analysis.copy()
    fig_yearly = dp.analyze_attack_types_time_series(df_analysis_copy, frequency='year')
    df_analysis_copy = df_analysis.copy()
    fig_top_5 = dp.top_5_vulnerability_bar_graph(df_analysis_copy)

    # Convert to JSON
    graphJSON = fig_yearly.to_json()
    graphJSON2 = fig_top_5.to_json()

    return render_template('vulnerabilities.html', graphJSON=graphJSON, graphJSON2=graphJSON2)


@app.route('/ransomware')
def ransomware_attacks():
    filename = 'Dataset/Full_FYP_crawled_edit.csv'
    start_year = '2000'
    end_year = '2021'

    year_country_counts = dp.count_countries_by_year_range(filename, start_year, end_year)
    fig = dp.plot_ransomware_attacks(year_country_counts)
    # pio.show(fig)

    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)  # Convert the graph to JSON

    return render_template('Ransomware.html', graphJSON=graphJSON)


@app.route('/predict')
def plot():
    predict_scores = None
    return render_template('predict.html', predict_scores=predict_scores, synthetic_data=None)


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

    return render_template('predict.html', graphJSON=graphJSON, predict_scores=predict_scores, accuracy=accuracy)


@app.route('/generate', methods=['POST'])
def generate():
    user_generate = int(request.form.get('user_generate'))

    synthetic_data = dp.generate_synthetic_data(df, num_samples=user_generate)

    # Train the model and get predicted probabilities
    vulnerability_model = ml.VulnerabilityModel(df)

    y_test, y_pred_proba, X_test = vulnerability_model.train_model(3)

    y_pred = vulnerability_model.predict(synthetic_data)
    y_pred_numeric = y_pred.astype(int)

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

    trace2 = go.Histogram(
        x=y_pred_numeric,  # Corrected here to use y_pred_numeric as x data
        opacity=0.75,
        name='Predicted'
    )

    data = [trace0, trace1, trace2]

    # Convert to JSON
    graphJSON = json.dumps(data, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('predict.html', graphJSON=graphJSON, synthetic_data=synthetic_data, y_pred=y_pred_numeric)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
