from flask import Flask, render_template

app = Flask(__name__)


import config

import models

import routes

@app.route('/')

def index():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)
