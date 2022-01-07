from flask import Flask, render_template
from OpenSSL import SSL

app = Flask(__name__)

@app.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')


@app.route('/register')
def register():
    return {}


@app.route('/challenge')
def challenge():
    return {}


if __name__ == '__main__':
    app.run(ssl_context=("cert.pem", "key.pem"), debug=True)
