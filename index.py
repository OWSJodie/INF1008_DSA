from flask import Flask
from flask import render_template
from flask import redirect
from flask import request

import pandas as pd
import json
import plotly
import plotly.express as px
import plotly.graph_objs as go

import algorithm.analysis as analysis

app = Flask(__name__)

file_location = 'dataset/updated_cve_2023_07_09.xlsx'

mapping = {
    'LOW': 2.5,
    'MEDIUM': 5,
    'HIGH': 7.5,
    'CRITICAL': 10
}

global df, filtered_df
df = analysis.load_data(file_location)
df = analysis.map_words_to_values(df, 'Mixed_baseSeverity', mapping)

variables_of_interest = ['Mixed_exploitabilityScore',
                         'Mixed_impactScore',
                         'Mixed_baseSeverity',
                         'Mixed_basedScore']

# Remove all score which is 0 or na
filtered_df = df[(df[variables_of_interest] != 0).dropna().all(axis=1)]


@app.route('/')
def index():
    return redirect("/analytics", code=302)


# @app.route('/analytics')
# def analytics():
#     test_data = [
#         {"RansomAttack": "WannaCry", "Industry": "Education", "average_cost": 5},
#         {"RansomAttack": "Locky", "Industry": "Education", "average_cost": 10},
#         {"RansomAttack": "Ryuk", "Industry": "Education", "average_cost": 8},
#         {"RansomAttack": "WannaCry", "Industry": "Health", "average_cost": 3},
#         {"RansomAttack": "Locky", "Industry": "Health", "average_cost": 4},
#         {"RansomAttack": "Ryuk", "Industry": "Health", "average_cost": 11}
#     ]
#
#     RansomAttack = [dic["RansomAttack"] for dic in test_data]
#     Industry = [dic["Industry"] for dic in test_data]
#     average_cost = [dic["average_cost"] for dic in test_data]
#
#     df = pd.DataFrame({
#         'RansomAttack': RansomAttack,
#         'Industry': Industry,
#         'average_cost': average_cost
#     })
#     fig = px.bar(df, x='RansomAttack', y='average_cost', color='Industry', barmode='group')
#     graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
#
#     return render_template('analytics.html', graphJSON=graphJSON)


@app.route('/resources')
def resources():
    return render_template('resources.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/analytics')
def analytics():
    global df, filtered_df

    # Perform your analysis
    # analysis_df = analysis.analyze_attack_vectors(filtered_df, 5)

    # Get a dictionary of yearly vulnerabilities dataframes
    vulnerability_dict = analysis.store_vulnerabilities_in_dict(filtered_df, 'vulnerability', True)

    # Create a list of line traces
    traces = []
    for vulnerability, df in vulnerability_dict.items():
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
