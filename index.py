from flask import Flask
from flask import render_template
from flask import redirect
from flask import request

app = Flask(__name__)

@app.route('/')
def index():
    return redirect("/analytics", code=302)

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__=="__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)