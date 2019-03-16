from datetime import datetime
from flask import Flask, request, session, redirect, render_template, url_for, \
    send_file
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from functools import wraps
from wtforms import StringField, PasswordField, SubmitField, \
    TextAreaField
from wtforms.fields.html5 import DateField
import hashlib
from dateutil import parser
from wtforms.validators import DataRequired, Length
from libgravatar import Gravatar
from io import BytesIO

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


class SettingsForm(FlaskForm):
    email = StringField('Почта')
    password = PasswordField('Пароль')
    name = StringField("Имя", validators=[Length(max=10)])
    surname = StringField("Фамилия", validators=[Length(max=25)])
    about_me = TextAreaField("О себе", validators=[Length(max=240)])
    date = DateField("Дата рождения")
    submit = SubmitField("Применить")


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
    date = DateField("Дата рождения")
    password = PasswordField('Пароль',
                             validators=[DataRequired("Введите пароль"),
                                         Length(6)])
    retype_password = PasswordField('Повторите Пароль',
                                    validators=[
                                        DataRequired("Введите пароль ещё раз")])
    email = StringField("Почта", validators=[DataRequired("Введите Email"),
                                             Length(max=120)])
    submit = SubmitField("Регистрация")


class ArticleForm(FlaskForm):
    title = StringField("Название",
                        validators=[DataRequired("Введите название!"),
                                    Length(max=64)])
    content = TextAreaField("Текст статьи",
                            validators=[DataRequired("Введите текст!"),
                                        Length(max=4096)])
    file = FileField("Дополнительные файлы")
    submit = SubmitField("Отправить")


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
    is_beta = db.Column(db.Boolean, unique=False, default=False)
    is_admin = db.Column(db.Boolean, unique=False, default=False)
    articles = db.relationship('Article',
                               backref=db.backref('Author',
                                                  lazy=True))

    def __repr__(self):
        return '<User {} {} {} {}>'.format(
            self.id, self.username, self.name, self.surname)


class Relations(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    friend_from = db.Column(db.Integer)
    friend_to = db.Column(db.Integer)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(64), unique=False, nullable=True)
    content = db.Column(db.String(4096), unique=False, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_with_files = db.Column(db.Boolean, nullable=False)
    files = db.relationship("FileInArticle", backref="Files", lazy=True)

    def __repr__(self):
        return '<Article {} {} {}>'.format(
            self.id, self.user_id, self.timestamp)


class FileInArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(4096), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))
    file = db.Column(db.LargeBinary, nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.String(4096), nullable=False)
    from_user_id = db.Column(db.Integer, nullable=False)
    to_user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Message {} {} {}>'.format(
            self.id, self.from_user_id, self.to_user_id)


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
            id=session.get('id')).first()
        user = User.query.filter_by(id=ident).first()
        rel = Relations.query.filter_by(friend_from=sender.id,
                                        friend_to=user.id)
        if t == "ad":
            if user.id != sender.id and not rel.first():
                rel = Relations(friend_from=sender.id, friend_to=user.id)
                db.session.add(rel)
                db.session.commit()
        elif t == "rm":
            if user.id != sender.id and rel.first():
                rel.delete()
                db.session.commit()


@app.route("/chat/id<int:ident>", methods=['GET', 'POST'])
@login_required
def chat(ident):
    user = User.query.filter_by(id=session.get("id")).first()
    to_user = User.query.filter_by(id=ident).first()
    if not to_user:
        return redirect("/404")
    if request.method == "POST":
        if request.form.get("message_text"):
            msg = Message(text=request.form.get("message_text"),
                          from_user_id=session.get("id"), to_user_id=ident)
            db.session.add(msg)
            db.session.commit()
    messages = list(
        reversed(sorted(Message.query.filter_by(from_user_id=user.id,
                                                to_user_id=to_user.id)
                        .all() +
                        Message.query.filter_by(
                            from_user_id=to_user.id,
                            to_user_id=user.id).all(),
                        key=lambda x: -x.id)[:100]))
    users = {user.id: user,
             to_user.id: to_user}
    return render_template("chat.html", ident=ident, messages=messages,
                           users=users)


@app.route("/", methods=['POST', 'GET'])
@app.route("/feed", methods=['POST', 'GET'])
@login_required
def index():
    articles = list(reversed(
        sorted(
            [Article.query.filter_by(user_id=i.friend_to).all()[:-5:-1] for i in
             Relations.query.filter_by(
                 friend_from=session.get("id")).all()])))[:20]
    try:
        if not articles[0]:
            articles = []
        else:
            articles = [(art, User.query.filter_by(id=art[0].user_id).first())
                        for
                        art
                        in
                        articles if art]
    except Exception as e:
        print(e)
        articles = []
    return render_template("feed.html", articles=articles)


@app.route("/login", methods=['POST', 'GET'])
def login():
    if session.get("username", None) is not None:
        return redirect("/feed")
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
                return redirect("/feed")
            else:
                form.username.errors.append(
                    "Пользователь с парой Логин+Пароль не найден!")
    return render_template("login.html", session=session, form=form)


@app.route("/register", methods=['POST', 'GET'])
def register():
    if session.get("username", None) is not None:
        return redirect("/feed")
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
                    return redirect("/feed")
                except Exception as e:
                    print(e)
                    form.username.errors.append(
                        "Ошибка при создании профиля!")
    return render_template("register.html", session=session, form=form)


# TODO This thing
@app.route("/user/id<int:identificator>/settings", methods=['GET', 'POST'])
@login_required
def settings(identificator):
    if identificator != session.get("id") and not session.get("is_admin"):
        return redirect("/404")
    else:
        user = User.query.filter_by(id=identificator).first()
        form = SettingsForm()
        if request.method == "POST":
            if form.validate_on_submit():
                if "@" not in request.form["email"]:
                    form.email.errors.append("Введите реальную почту!")
                elif request.form.get("email") != "":
                    user.email = request.form["email"]
                    user.avatar_path = Gravatar(request.form['email']) \
                        .get_image(248)
                if request.form.get("password") != "":
                    m = hashlib.md5()
                    m.update(
                        (request.form["password"]).encode(
                            'UTF-8'))
                    user.password_hash = m.hexdigest()
                if request.form.get("name") != "":
                    user.name = request.form["name"]
                if request.form.get("surname") != "":
                    user.surname = request.form["surname"]
                if request.form.get("about_me") != "":
                    user.about_me = request.form["about_me"]
                if request.form.get("date") != "":
                    user.date = parser.parse(request.form['date'])
                db.session.commit()
                return redirect(f"/user/id{identificator}")
        return render_template("settings.html", username=user.username,
                               api_key=user.api_key, session=session,
                               form=form,
                               who=user.name + " " + user.surname)


@app.route('/users', methods=['GET', 'POST'])
@app.route("/user/id<int:identificator>/subscribes",
           methods=["GET", "POST"])
@login_required
def get_friends(identificator=None):
    query = None
    if request.method == "POST":
        if request.args.get("sort", None) not in sort_types:
            session["sort_type"] = sort_types[0]
        else:
            session["sort_type"] = request.args["sort"]
        if request.form.get("query", None) is not None:
            query = request.form["query"]
    if identificator is None:
        message = "Пользователи"
        who = ""
        if query is not None:
            friends = list(filter(lambda
                                      x: query.lower() in x.name.lower()
                                         or query.lower() in x.surname.lower()
                                         or query.lower() in
                                         x.name.lower() + " " +
                                         x.surname.lower(),
                                  User.query.all()))
        else:
            friends = User.query.all()
    else:
        user = User.query.filter_by(
            id=identificator).first()
        message = "Подписки пользователя"
        who = f"{user.name} {user.surname}".title()
        fr = [User.query.filter_by(id=rel.friend_to).first() for rel in
              Relations.query.filter_by(friend_from=user.id).all()]
        if query is not None:
            friends = list(filter(lambda
                                      x: query.lower() in x.name.lower()
                                         or query.lower()
                                         in x.surname.lower()
                                         or query.lower() in
                                         x.name.lower() + " " +
                                         x.surname.lower(),
                                  fr))
        else:
            friends = fr
    return render_template("friends.html", ident=identificator,
                           friends=friends, message=message,
                           who=who)


@app.route("/user/id<int:identificator>/subscribers",
           methods=["GET", "POST"])
@login_required
def get_subscribers(identificator):
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
    who = f"{user.name} {user.surname}".title()
    fr = [User.query.filter_by(id=rel.friend_from).first() for rel in
          Relations.query.filter_by(friend_to=user.id).all()]
    if query is not None:
        friends = list(filter(lambda
                                  x: query.lower() in x.name.lower()
                                     or query.lower()
                                     in x.surname.lower()
                                     or query.lower() in
                                     x.name.lower() + " " +
                                     x.surname.lower(),
                              fr))
    else:
        friends = fr
    return render_template("friends.html", ident=identificator,
                           friends=friends, message="Подписчики пользователя",
                           who=who)


@app.route("/user/id<int:identificator>", methods=['GET', 'POST'])
@login_required
def user_page(identificator):
    user = User.query.filter_by(
        id=identificator).first()
    if user is None:
        return redirect("/404")
    self = User.query.filter_by(
        id=session.get('id')).first()
    is_friend = True if Relations.query.filter_by(friend_from=self.id,
                                                  friend_to=user.id).all() \
        else False
    qty = len(Relations.query.filter_by(friend_from=user.id).all())
    qty_sb = len(Relations.query.filter_by(friend_to=user.id).all())
    form = ArticleForm()
    if form.validate_on_submit():
        if session.get("id") != identificator:
            return redirect("/404")
        art = Article(user_id=identificator, title=request.form.get("title"),
                      content=request.form.get("content"),
                      is_with_files=bool(request.files))
        if 'file' in request.files:
            nfile = FileInArticle(name=request.files['file'].filename,
                                  file=request.files['file'].stream.read())
            art.files.append(nfile)
            db.session.add(nfile)
        db.session.add(art)
        db.session.commit()
    articles = reversed(Article.query.filter_by(user_id=identificator).all())
    return render_template("user_page.html",
                           date=".".join(reversed(str(user.date).split("-"))),
                           user=user, is_friends=is_friend,
                           qty=qty,
                           qty_sb=qty_sb,
                           form=form, articles=articles)


@app.route("/addfriend/id<int:ident>",
           methods=["GET", "POST"])
@login_required
def add_friend(ident):
    if request.method == "POST":
        do_magic(ident, "ad")
    return redirect(f"/user/id{ident}")


@app.route("/rmfriend/id<int:ident>", methods=["GET", "POST"])
@login_required
def remove_friend(ident):
    if request.method == "POST":
        do_magic(ident, "rm")
    return redirect(f"/user/id{ident}")


@app.route("/delete_article/<int:ident>")
@login_required
def delete_article(ident):
    art = Article.query.filter_by(id=ident)
    idnt = art.first().user_id
    if art.first() and (idnt == session.get("id") or session.get("is_admin")):
        if art.first().is_with_files:
            FileInArticle.query.filter_by(id=art.first().files[0].id).delete()
        art.delete()
        db.session.commit()
    return redirect(f"/user/id{idnt}")


@app.route("/get_file/<int:ident>")
@login_required
def get_file(ident):
    file = FileInArticle.query.filter_by(id=ident).first()
    if file:
        return send_file(BytesIO(file.file), attachment_filename=file.name,
                         as_attachment=True)
    else:
        redirect("/404")


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
