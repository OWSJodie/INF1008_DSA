from flask import Flask
from flask import render_template
from flask import redirect
from flask import request

import pandas as pd
import json
import plotly
import plotly.express as px

app = Flask(__name__)

@app.route('/')
def index():
    return redirect("/analytics", code=302)

@app.route('/analytics')
def analytics():
    test_data = [
        {"RansomAttack": "WannaCry", "Industry": "Education", "average_cost": 5},
        {"RansomAttack": "Locky", "Industry": "Education", "average_cost": 10},
        {"RansomAttack": "Ryuk", "Industry": "Education", "average_cost": 8},
        {"RansomAttack": "WannaCry", "Industry": "Health", "average_cost": 3},
        {"RansomAttack": "Locky", "Industry": "Health", "average_cost": 4},
        {"RansomAttack": "Ryuk", "Industry": "Health", "average_cost": 11}
    ]

    RansomAttack = [dic["RansomAttack"] for dic in test_data]
    Industry = [dic["Industry"] for dic in test_data]
    average_cost = [dic["average_cost"] for dic in test_data]

    df = pd.DataFrame({
        'RansomAttack': RansomAttack,
        'Industry': Industry,
        'average_cost': average_cost
      })
    fig = px.bar(df, x='RansomAttack', y='average_cost', color='Industry', barmode='group')
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('analytics.html', graphJSON=graphJSON)
    

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__=="__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)