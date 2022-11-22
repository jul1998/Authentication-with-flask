from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, jsonify

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager.init_app(app)
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("User already exists")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password,method='pbkdf2:sha256', salt_length=2)
        new_user = User(email=email, name=name, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template("secrets.html", name=new_user.name)

    return render_template("register.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            user = User.query.filter_by(email=email).first()
            print(user.email)
        except:
            flash("User does not exist")
            return redirect(url_for("login"))
        else:
            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    print(user.is_authenticated)
                    return render_template("secrets.html", name=user.name, logged_in=user.is_authenticated)
                else:
                    print(user.is_authenticated)
                    return jsonify("Password does not match")

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download/')
@login_required
def download():
    return send_from_directory(
        directory="static", path="files/cheat_sheet.pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
