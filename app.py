import json
import os
import webhook_utils
from flask import Flask, request, render_template, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from webhook_utils import send_webhook

app = Flask(__name__)

webhook_utils.send_webhook("Titolo", "descrizione asd asd asd", "asd")

with open("config.json") as f: # Si apre il file json per leggere il contenuto
    config = json.load(f) # Tutto il contenuto viene salvato in un dizionario
    app.config["SECRET_KEY"] = config["SECRET_KEY"]
    app.config["SQLALCHEMY_DATABASE_URI"] = config["SQLALCHEMY_DATABASE_URI"]
    app.config['UPLOAD_FOLDER'] = config["UPLOAD_FOLDER"]
    app.config['MAX_CONTENT_LENGTH'] = config["MAX_CONTENT_LENGTH"]
    ALLOWED_EXTENSIONS = config["ALLOWED_EXTENSIONS"]

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy()
db.init_app(app) # si inizializza il database

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) #la variabile id viene salvata come prima colonna del database (primary_key) è di tipo integer per semplicità
    email = db.Column(db.String, unique=True, nullable=False) # la variabile email viene salvata come seconda colonna come stringa. Non possono esserci due indirizzi uguali e ciascun utente deve avere un indirizzo
    password_hash = db.Column(db.String, nullable=False) # la password viene salvata come hash per questioni di sicurezza. Non può essere letta se non dopo averla craccata tramite brute force
    files = db.relationship('File', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password) # Nel settare la password dell'utente viene generata e salvata l'hash

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) # Per controllare la password bisogna calcolare l'hash della password e confrontarlo il che viene fatto dalla libreria perchè siamo in python che è un linguaggio da bambini


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String, nullable=False)
    original_filename = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirmation = request.form['confirmation']

        if password != confirmation:
            return "Passwords don't match"

        if User.query.filter_by(email=email).first():
            return "Email address already in use"

        with app.app_context():
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template("register.html")

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        # This handles the upload (we already have this code)
        return upload_file()
    # If it's a GET request, show the upload form
    return render_template('upload.html')

#@app.route('/upload', methods=['GET', 'POST'])
#@login_required
def upload():
    if request.method == 'POST':
        # This handles the upload (we already have this code)
        return upload_file()
    # If it's a GET request, show the upload form
    return render_template('upload.html')
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return "no file"
    file = request.files['file']
    if file.filename == '':
        return "no file"

    if file and allowed_file(file.filename):
        from werkzeug.utils import secure_filename
        original_filename = secure_filename(file.filename)
        filename = f"{current_user.id}_{original_filename}" # per evitare di aver file con nomi uguali

        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_file = File(
            filename=filename,
            original_filename=original_filename,
            user_id=current_user.id
        )

        db.session.add(new_file)
        db.session.commit()

        return "File uploaded successfully!"
    return "File type not supported :("

@app.route('/files')
@login_required
def files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template("files.html", files=files)

@app.route('/files/<filename>')
@login_required
def view_file(filename):
    # Check if the file belongs to the current user
    file = File.query.filter_by(filename=filename, user_id=current_user.id).first()
    if file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    return 'File not found', 404

@app.route('/dashboard')
@login_required
def dashboard():
    return f"You're logged in as {current_user.email.replace("@itiszuccante.edu.it", "").split(".")}"

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        send_webhook(request.form["title"], request.form["description"], request.form["sender"])
    return render_template("support.html")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug = True)
