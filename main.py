from flask import Flask, request, session, redirect, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SubmitField, \
    TextAreaField
import hashlib
from dateutil import parser
from wtforms.validators import DataRequired, Length
from libgravatar import Gravatar

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = url = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "sup3rs3cre1p@ssvv0rd"
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired("Введите имя пользователя")])
    password = PasswordField('Пароль',
                             validators=[DataRequired("Введите пароль")])
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    name = StringField("Имя", validators=[DataRequired("Введите имя"),
                                          Length(max=10)])
    surname = StringField("Фамилия",
                          validators=[DataRequired("Введите фамилию"),
                                      Length(max=25)])
    about_me = TextAreaField("О себе", validators=[
        DataRequired("Расскажите о себе (240 символов)"),
        Length(max=240)])
    username = StringField("Логин", validators=[
        DataRequired("Введите имя пользователя"),
        Length(max=80)])
    date = DateField("Дата рождения", format='%d.%m.%Y',
                     validators=[DataRequired("Введите дату рождения")])
    password = PasswordField('Пароль',
                             validators=[DataRequired("Введите пароль")])
    retype_password = PasswordField('Повторите Пароль',
                                    validators=[
                                        DataRequired("Введите пароль ещё раз")])
    email = StringField("Почта", validators=[DataRequired("Введите Email"),
                                             Length(max=120)])
    submit = SubmitField("Регистрация")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(10), unique=False, nullable=False)
    surname = db.Column(db.String(25), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    about_me = db.Column(db.String(240), nullable=True)
    password_hash = db.Column(db.String(128), unique=False, nullable=False)
    avatar_path = db.Column(db.String(400), nullable=True, unique=False)
    api_key = db.Column(db.String(35), unique=True, nullable=False)
    date = db.Column(db.Date(), unique=False,
                     nullable=False)
    is_admin = db.Column(db.Boolean, unique=False, default=False)

    def __repr__(self):
        return '<User {} {} {} {}>'.format(
            self.id, self.username, self.name, self.surname)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, unique=False, nullable=False)
    title = db.Column(db.String(64), unique=False, nullable=True)
    content = db.Column(db.String(4096), unique=False, nullable=False)
    date_time = db.Column(db.DateTime(timezone=True), unique=False,
                          nullable=False)
    is_with_files = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<Article {} {} {}>'.format(
            self.id, self.user_id, self.date_time)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.String(4096), nullable=False)
    from_user = db.Column(db.Integer, unique=False, nullable=False)
    to_user = db.Column(db.Integer, unique=False, nullable=False)
    date_time = db.Column(db.DateTime(timezone=True), unique=False,
                          nullable=False)
    is_with_files = db.Column(db.Boolean, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return '<Message {} {} {} {}>'.format(
            self.id, self.from_user, self.to_user, self.date_time)


class Relations(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    from_friend = db.Column(db.Integer, nullable=False)
    to_friend = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Relation {self.from_friend} {self.to_friend}>"


@app.route("/", methods=['POST', 'GET'])
@app.route("/index", methods=['POST', 'GET'])
def index():
    if session.get("username", None) is not None:
        return redirect(f"/user/{session.get('id')}")
    return redirect("/login")


@app.route("/login", methods=['POST', 'GET'])
def login():
    if session.get("username", None) is not None:
        return redirect("/index")
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            m = hashlib.md5()
            m.update(
                request.form['password'].encode(
                    'UTF-8'))
            user = User.query.filter_by(
                username=request.form['username']).first()
            if user and user.password_hash == m.hexdigest():
                session['id'] = user.id
                session['username'] = user.username
                session['api_key'] = user.api_key
                session['is_admin'] = user.is_admin
                return redirect("/index")
            else:
                form.username.errors.append(
                    "Пользователь с парой Логин+Пароль не найден!")
    return render_template("login.html", session=session, form=form)


@app.route("/register", methods=['POST', 'GET'])
def register():
    if session.get("username", None) is not None:
        return redirect("/index")
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            if request.form['password'] != request.form['retype_password']:
                form.password.errors.append("Пароли не совпадают!")
            else:
                try:
                    m = hashlib.md5()
                    m.update(
                        request.form['password'].encode(
                            'UTF-8'))
                    m1 = hashlib.md5()
                    m1.update(request.form['username'].encode("UTF-8"))
                    avatar = Gravatar(request.form['email']).get_image(248)
                    new_user = User(username=request.form['username'],
                                    name=request.form['name'],
                                    about_me=request.form['about_me'],
                                    surname=request.form['surname'],
                                    email=request.form['email'],
                                    avatar_path=avatar,
                                    password_hash=m.hexdigest(),
                                    date=parser.parse(request.form['date']),
                                    api_key=m1.hexdigest())
                    db.session.add(new_user)
                    db.session.commit()
                    user = User.query.filter_by(
                        username=new_user.username).first()
                    session['id'] = user.id
                    session['username'] = user.username
                    session['api_key'] = user.api_key
                    session['is_admin'] = user.is_admin
                    return redirect("/index")
                except Exception as e:
                    print(e)
                    form.username.errors.append(
                        "Ошибка при создании профиля!")
    return render_template("register.html", session=session, form=form)


@app.route("/user/<int:identificator>")
def user_page(identificator):
    if session.get("username", None) is None:
        return redirect("/login")
    user = User.query.filter_by(
        id=identificator).first()
    if user is None:
        return redirect("/404")
    user.date = ".".join(reversed(str(user.date).split("-")))
    return render_template("user_page.html", user=user)


@app.route("/404")
@app.errorhandler(404)
def error():
    return render_template("404.html")


@app.route("/logout")
def logout():
    if session.get("username", None) is not None:
        session.clear()
    return redirect("/index")


if __name__ == "__main__":
    db.create_all()
    app.run(host="0.0.0.0", port=80)
