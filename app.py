import json
from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)

with open("config.json") as f: # Si apre il file json per leggere il contenuto
    config = json.load(f) # Tutto il contenuto viene salvato in un dizionario
    app.config["SECRET_KEY"] = config["SECRET_KEY"]
    app.config["SQLALCHEMY_DATABASE_URI"] = config["SQLALCHEMY_DATABASE_URI"]

db = SQLAlchemy()
db.init_app(app) # si inizializza il database

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) #la variabile id viene salvata come prima colonna del database (primary_key) è di tipo integer per semplicità
    email = db.Column(db.String, unique=True, nullable=False) # la variabile email viene salvata come seconda colonna come stringa. Non possono esserci due indirizzi uguali e ciascun utente deve avere un indirizzo
    password_hash = db.Column(db.String, nullable=False) # la password viene salvata come hash per questioni di sicurezza. Non può essere letta se non dopo averla craccata tramite brute force

    def set_password(self, password):
        self.password_hash = generate_password_hash(password) # Nel settare la password dell'utente viene generata e salvata l'hash

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) # Per controllare la password bisogna calcolare l'hash della password e confrontarlo il che viene fatto dalla libreria perchè siamo in python che è un linguaggio da bambini


login_manager = LoginManager(app)

@app.route('/create_test_user')
def create_test_user():
    with app.app_context():
        if not User.query.filter_by(email='test@test.com').first():
            user = User(email='test@test.com')
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
            return 'Test user created!'
    return 'Test user already exists!'


@app.route('/')
def hello_world():  # put application's code here
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/rules')
def rules():
    return render_template("rules.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST': # se viene inviata una richiesta di login
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password): # se l'utente esiste e la password è corretta
            login_user(user) # si fa il login
            return redirect(url_for('dashboard')) # e lo si passa alla dashboard

        return "Email or password is incorrect" # altrimenti si dice che i dati sono sbagliati
    return render_template('login.html') # se il tipo di richiesta non è POST, l'utente sta caricando la pagina di login

@app.route('/dashboard')
@login_required
def dashboard():
    return "You're logged in!"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug = True)
