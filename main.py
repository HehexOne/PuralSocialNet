from flask import Flask, request, session, redirect, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from functools import wraps
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

sort_types = ["name", "id", "order_in_db"]


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
                             validators=[DataRequired("Введите пароль"),
                                         Length(6)])
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
    friend_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    friends = db.relationship('User',
                              backref=db.backref('Friends',
                                                 lazy=True), remote_side=[id])
    is_beta = db.Column(db.Boolean, unique=False, default=False)
    is_admin = db.Column(db.Boolean, unique=False, default=False)

    def __repr__(self):
        return '<User {} {} {} {}>'.format(
            self.id, self.username, self.name, self.surname)


class Music(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id'),
                        nullable=False)
    user = db.relationship('User',
                           backref=db.backref('Articles',
                                              lazy=True))
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
    from_user_id = db.Column(db.Integer, nullable=False)
    to_user_id = db.Column(db.Integer, nullable=False)
    date_time = db.Column(db.DateTime(timezone=True), unique=False,
                          nullable=False)
    is_with_files = db.Column(db.Boolean, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return '<Message {} {} {} {}>'.format(
            self.id, self.from_user, self.to_user, self.date_time)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("username") is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def do_magic(ident, t):
    if request.form['api_key'] != session.get('api_key'):
        pass
    else:
        sender = User.query.filter_by(
            api_key=session.get('api_key')).first()
        user = User.query.filter_by(id=ident).first()
        if user.id != sender.id and user.id not in sender.Friends:
            sender.Friends.append(user) if t == "ad" else sender.Friends.remove(
                user)
            db.session.commit()


@app.route("/", methods=['POST', 'GET'])
@app.route("/index", methods=['POST', 'GET'])
@login_required
def index():
    return redirect(f"/user/id{session.get('id')}")


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
            elif " " in request.form["username"]:
                form.username.errors.append("В логине не должно быть пробелов!")
            elif "@" not in request.form["email"]:
                form.email.errors.append("Введите реальную почту!")
            elif User.query.filter_by(
                    username=request.form['username']).first() is not None:
                form.username.errors.append("Уже зарегестрирован!")
            else:
                try:
                    m = hashlib.md5()
                    m.update(
                        (request.form['password']).encode(
                            'UTF-8'))
                    m1 = hashlib.md5()
                    m1.update((request.form['username'] + request.form[
                                                              "password"][
                                                          2:5]).encode("UTF-8"))
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


# TODO This thing
@app.route("/user/id<int:identificator>/settings")
@login_required
def settings(identificator):
    pass


# TODO This thing
@app.route("/user/id<int:identificator>/friends/<int:page>",
           methods=["GET", "POST"])
@login_required
def get_friends(identificator, page):
    query = None
    if request.method == "POST":
        if request.args.get("sort", None) not in sort_types:
            session["sort_type"] = sort_types[0]
        else:
            session["sort_type"] = request.args["sort"]
        if request.form.get("query", None) is not None:
            query = request.form["query"]
    user = User.query.filter_by(
        id=identificator).first()
    message = "Друзья"
    who = f"{user.name} {user.surname}".title()
    qty = (len(user.Friends) // 20) * page
    if query is not None:
        friends = list(filter(lambda
                                  x: query.lower() in x.name.lower()
                                     or query.lower() in x.surname.lower(),
                              User.query.all()))[qty:qty + 20]
        message = "Пользователи"
        who = ""
    else:
        friends = user.Friends[qty:qty + 20]
    return render_template("friends.html", ident=identificator, friends=friends,
                           pages=range(len(user.Friends) // 20),
                           current_page=page, message=message,
                           who=who)


@app.route("/user/id<int:identificator>/friends")
@login_required
def friends(identificator):
    return redirect(f"/user/id{identificator}/friends/1")


@app.route("/user/id<int:identificator>")
@login_required
def user_page(identificator):
    user = User.query.filter_by(
        id=identificator).first()
    if user is None:
        return redirect("/404")
    self = User.query.filter_by(
        id=session.get('id')).first()
    is_friend = True if user in self.Friends else False
    qty = len(user.Friends)
    user.date = ".".join(reversed(str(user.date).split("-")))
    return render_template("user_page.html", user=user, is_friends=is_friend,
                           qty=qty)


@app.route("/addfriend/id<int:ident>", methods=["GET", "POST"])
@login_required
def add_friend(ident):
    if request.method == "POST":
        if request.form['api_key'] != session.get('api_key'):
            pass
        else:
            sender = User.query.filter_by(
                api_key=session.get('api_key')).first()
            user = User.query.filter_by(id=ident).first()
            if user.id != sender.id and user.id not in sender.Friends:
                sender.Friends.append(user)
                db.session.commit()
    return redirect(f"/user/id{ident}")


@app.route("/rmfriend/id<int:ident>", methods=["GET", "POST"])
@login_required
def remove_friend(ident):
    if request.method == "POST":
        do_magic(ident, "rm")
    return redirect(f"/user/id{ident}")


@app.errorhandler(404)
def error_404(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


@app.route("/error")
def err():
    return error_404("a")


@app.route("/logout")
def logout():
    if session.get("username", None) is not None:
        session.clear()
    return redirect("/login")


if __name__ == "__main__":
    db.create_all()
    app.run(host="0.0.0.0", port=80)
