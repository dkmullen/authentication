from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email. Log in instead!")
            return redirect(url_for('login'))

        new_user = User(
            email=request.form['email'],
            name=request.form['name'],
            password=generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        )
        # Or this
        # new_user = User(
        #     email=request.form.get('email'),
        #     name=request.form.get('name'),
        #     password=request.form.get('password')
        # )
        db.session.add(new_user)
        db.session.commit()
        return render_template('secrets.html', name=new_user.name)
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        registered_user = User.query.filter_by(email=request.form['email']).first()
        if not registered_user:
            # Email doesn't exist
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(registered_user.password, request.form['password']):
            # Password incorrect
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(registered_user)
            flash('Logged in successfully.')
            return redirect(url_for('secrets'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    print('Kick ass, man.')
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
