import base64
import functools
import hashlib
import os
import uuid

import click
import flask
import flask_bcrypt
import flask_sqlalchemy
import flask_wtf
import wtforms
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property


#######################
# APPLICATION CONFIG #
######################

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "]\x9f\xad\xbe\xc9\xfc\r\xc9(u\x91\x82P\xe8\xa5\x10\x13\x982-\x1b\x90^\x18W\x0c\xea\x8e)8x0"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///testing.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = flask_sqlalchemy.SQLAlchemy(app)
bcrypt = flask_bcrypt.Bcrypt(app)


###########
# HELPERS #
###########

@app.shell_context_processor
def make_shell_context():
    return globals()


@app.cli.command()
def add_schools():
    schools = (
        "Sancta Maria College",
        "Sancta Maria Primary",
        "Random Other School"
    )
    for i in schools:
        db.session.add(School(i))
        click.echo("Added " + i)
    db.session.commit()


def state_handler(definition):
    def hash_request(request):
        return hashlib.sha256(
            ''.join([
                request.host,
                ','.join(request.accept_charsets.values()),
                ','.join(request.accept_encodings.values()),
                ','.join(request.accept_languages.values()),
                request.user_agent.string
            ]).encode()
        ).hexdigest()

    @functools.wraps(definition)
    def wrapper(*args, **kwargs):
        state_id = flask.request.cookies.get("game-state")
        hashed_request = hash_request(flask.request)
        if state_id is not None \
                and State.id_exists(state_id) \
                and State.query.get(state_id).request_hash == hashed_request:
            state = State.query.get(state_id)
        else:
            state = State(hashed_request)
            db.session.add(state)
            db.session.commit()
        response = definition(*args, **kwargs, state=state)
        prepared_response = flask.make_response(response)
        prepared_response.set_cookie("game-state", value=state.id, httponly=True)
        return prepared_response

    return wrapper


############
# DATABASE #
############

class Model:
    @classmethod
    def id_exists(cls, id):
        return cls.query.get(id) is not None


class State(db.Model, Model):
    __tablename__ = "state"
    id = db.Column(db.String(64), primary_key=True)
    request_hash = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, default=None)
    user = db.relationship('User', uselist=False, back_populates="state")
    score = db.Column(db.Integer, default=0)

    def __init__(self, request_hash, user=None):
        self.id = self.generate_id()
        self.request_hash = request_hash
        if user is not None:
            self.user = user

    @staticmethod
    def generate_id():
        while True:
            potential_id = hashlib.sha256(os.urandom(128)).hexdigest()
            if not State.id_exists(potential_id):
                return potential_id


class School(db.Model, Model):
    __tablename__ = "school"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    students = db.relationship('User', back_populates="school")

    def __init__(self, name):
        self.name = name


class User(db.Model, Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    cards = db.relationship('Card')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)
    school = db.relationship('School', back_populates="students")
    state = db.relationship('State', back_populates="user")
    username = db.Column(db.String(10), nullable=False)
    _password = db.Column(db.Binary(60), nullable=False)
    salt = db.Column(db.String(24), nullable=False)
    highscore = db.Column(db.Integer, default=None)

    db.UniqueConstraint('username', 'school')

    def __init__(self, username, password, school):
        self.username = username
        self.password = password
        self.school = school

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plain_password):
        self.salt = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode()
        salted_password = plain_password + self.salt
        self._password = bcrypt.generate_password_hash(salted_password)

    @hybrid_method
    def check_password(self, plain_password):
        salted_password = plain_password + self.salt
        return bcrypt.check_password_hash(self.password, salted_password)


class Card(db.Model, Model):
    __tablename__ = "card"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    question = db.Column(db.String(30), nullable=False)
    answer = db.Column(db.String(30), nullable=False)

    def __init__(self, user, question, answer):
        self.user = user
        self.question = question
        self.answer = answer

    def render(self):
        return self.question


##########
# FORMS #
#########

class LoginForm(flask_wtf.FlaskForm):
    username = wtforms.StringField("Username",
                                   validators=[wtforms.validators.DataRequired(), wtforms.validators.Length(max=10)])
    password = wtforms.PasswordField("Password", validators=[wtforms.validators.DataRequired()])
    school = QuerySelectField('School', query_factory=lambda: School.query.order_by('name').all(), get_label='name',
                              allow_blank=False, get_pk=lambda a: a.id, validators=[wtforms.validators.DataRequired()])
    user = None

    def validate(self):
        if not flask_wtf.FlaskForm.validate(self):
            return False
        else:
            user = User.query.filter_by(username=self.username.data, school_id=self.school.data.id).first()
            if user is None:
                self.username.errors.append("Incorrect Username Or Password")
                return False
            elif not user.check_password(self.password.data):
                self.username.errors.append("Incorrect Username Or Password")
                return False
            else:
                self.user = user
                return True


class RegisterForm(flask_wtf.FlaskForm):
    username = wtforms.StringField("Username", validators=[wtforms.validators.DataRequired(),
                                                           wtforms.validators.Length(max=10)])
    password = wtforms.PasswordField("Password", validators=[wtforms.validators.DataRequired()])
    confirm_password = wtforms.PasswordField("Confirm Password", validators=[
        wtforms.validators.EqualTo('password', message="Passwords Do Not Match")])
    school = QuerySelectField('School', query_factory=lambda: School.query.order_by('name').all(),
                              get_label='name', allow_blank=False, get_pk=lambda a: a.id,
                              validators=[wtforms.validators.DataRequired()])

    @staticmethod
    def validate_username(form, username_field):
        if User.query.filter_by(username=username_field.data).first() is not None:
            raise wtforms.validators.ValidationError("Username Taken")


###########
# ROUTING #
###########

@app.route('/', methods=('GET',))
@state_handler
def index(state):
    if state.user is not None:
        return flask.redirect('/cards')
    else:
        return flask.render_template('index.jinja')


@app.route('/login', methods=('GET', 'POST'))
@state_handler
def login(state):
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data,
                                    school=form.school.data).first()
        state.user = user
        db.session.commit()
        return flask.redirect('/cards')
    else:
        return flask.render_template('login.jinja', form=form)


@app.route('/register', methods=('GET', 'POST'))
@state_handler
def register(state):
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(form.username.data, form.password.data, form.school.data)
        db.session.add(user)
        state.user = user
        db.session.commit()
        return flask.redirect('/cards')
    else:
        return flask.render_template('register.jinja', form=form)


@app.route('/cards', methods=('GET', 'POST'))
@state_handler
def cards(state):
    if state.user is None:
        flask.abort(403)
    else:
        return flask.render_template("cards.jinja", user=state.user)


@app.route('/api/add_card', methods=('POST',))
@state_handler
def add_card(state):
    q = flask.request.form.get('q')
    a = flask.request.form.get('a')
    card = Card(state.user, q, a)
    db.session.add(card)
    db.session.commit()
    return card.render()


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)
