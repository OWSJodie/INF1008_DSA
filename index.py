import json

import plotly
import plotly.graph_objs as go
from cybernews.cybernews import CyberNews
from flask import Flask
from flask import redirect
from flask import render_template

import algorithm.analysis as analysis

app = Flask(__name__)

file_location = 'dataset/updated_cve_2023_07_09.csv'

mapping = {
    'LOW': 2.5,
    'MEDIUM': 5,
    'HIGH': 7.5,
    'CRITICAL': 10
}

df = analysis.load_data(file_location)
df = analysis.map_words_to_values(df, 'Mixed_baseSeverity', mapping)

variables_of_interest = ['Mixed_exploitabilityScore',
                         'Mixed_impactScore',
                         'Mixed_baseSeverity',
                         'Mixed_basedScore']

filtered_df = df[(df[variables_of_interest] != 0).dropna().all(axis=1)]

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
@app.route('/analytics')
def analytics():
    global analysis_results

    # Perform analysis if results are not available
    if analysis_results is None:
        vulnerability_dict = analysis.store_vulnerabilities_in_dict(filtered_df, 'vulnerability', True)
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
