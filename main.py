#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""A Basic Card Game Using Flask"""

############
# METADATA #
############

__author__ = "Jackson Chadfield <chadfield.jackson@gmail.com>"

###########
# IMPORTS #
###########

import base64
import datetime
import functools
import hashlib
import os
import pathlib
import random
import uuid
import warnings
from typing import Any, Callable, Dict, Optional

import click
import flask
import flask_bcrypt
import flask_sqlalchemy
import flask_wtf
import wtforms
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property
from wtforms.ext.sqlalchemy.fields import QuerySelectField

#######################
# APPLICATION CONFIG #
######################

app = flask.Flask(__name__, instance_relative_config=True)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///database.db'  # Specify Where The Database Is
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Tracking Modifications Adds Unnecessary Overhead
app.config["ENABLE_BROWSER_HASH_CHECK"] = False
app.config["BCRYPT_LOG_ROUNDS"] = 15  # Number Of Rounds To Hash With Bcrypt
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False  # Fixes: https://github.com/pallets/flask/issues/2549

# Generate Secret Configs If Not Present
instance_folder = pathlib.Path('instance')
if not instance_folder.is_dir():
    warnings.warn("No Instance Folder: It will now be created")
    instance_folder.mkdir()
    conf_file = instance_folder / "config.py"
    conf_file.write_text("SECRET_KEY='{sk}'".format(sk=os.urandom(64).hex()))
app.config.from_pyfile('config.py')

# Load Plugins
db = flask_sqlalchemy.SQLAlchemy(app)  # ORM - Handles Database Operations
bcrypt = flask_bcrypt.Bcrypt(app)  # Handles Password Hashing


###########
# HELPERS #
###########

@app.shell_context_processor
def make_shell_context() -> Dict:
    """Helps In Development By Making All Variables Available For Testing"""
    return globals()


@app.cli.command()
def init() -> None:
    """Performs All Functions Needed To Initialise The App

    This Includes:
        * Rebuilding All Tables
        * Adding Test Data

    Run In A Command Shell With:
        >>> flask init
    """
    db.drop_all()
    click.echo("Dropped All Tables")
    db.create_all()
    click.echo("Created All Tables")
    schools = (
        "Sancta Maria College",
        "Sancta Maria Primary",
        "Random Other School"
    )
    for i in schools:
        db.session.add(School(i))
        click.echo("Added " + i)
    db.session.commit()


def state_handler(definition: Callable) -> Callable:
    """Handles Simple State Handling Between Requests

    Each callable that is wrapped with this handler will receive the current requests state.
    When the callable has returned its response, it is intercepted and assigned cookies.

    Args:
        definition (callable): A callable which operates within a flask.request context. Will be passed `state`.

    Returns:
        flask.Response: The response returned by `definition`, but wrapped with appropriate cookies.
    """

    @functools.wraps(definition)
    def wrapper(*args, **kwargs) -> flask.Response:
        """Main Wrapper For `state_handler`

        Returns:
            flask.Response with all cookies wrapped
        """
        state_id = flask.request.cookies.get("game-state")
        if state_id is not None and State.id_exists(state_id):
            # If state is valid, get it from the database
            state = State.query.get(state_id)
        else:
            # If it isn't valid, create a new State object
            state = State()
            db.session.add(state)
            db.session.commit()
        # Pass state to definition and get response
        kwargs['state'] = state
        response = definition(*args, **kwargs)
        # Set cookies on response
        prepared_response = flask.make_response(response)
        prepared_response.set_cookie("game-state", value=state.id, httponly=True)
        return prepared_response

    return wrapper


# IMPORTANT: This wrapper must be listed after @state_handler
def require_login(definition: Callable) -> Callable:
    """Convenience Method That Rejects All Unauthenticated Requests

    Apply this decorator to a route to require the user to be logged in.
    All unauthenticated responses will return a 403 FORBIDDEN code.

    IMPORTANT: This decorator must be applied after `state_handler`, as it requires the state.

    Args:
        definition (callable): A callable which operates within a flask.request context.

    Returns:
        The response of definition

    Raises:
        werkzeug.exceptions.Forbidden: If user attempt to access this resource without being logged in
    """

    @functools.wraps(definition)
    def wrapper(state: State, *args, **kwargs) -> flask.Response:
        if state.user is None:  # If No User Exists In State
            flask.abort(403)
        else:
            return definition(*args, **kwargs, state=state)  # Continue Request

    return wrapper


############
# DATABASE #
############

class CommonModelMixin:
    """Base Class For All Models In This App"""

    @classmethod
    def id_exists(cls: db.Model, id_: Any) -> bool:
        """Return If `id_` exists

        This is a mixin class inherited by all tables, allowing for easy, extensibility
        """
        return cls.query.get(id_) is not None


class State(db.Model, CommonModelMixin):
    """Represents The State Of Each Person Using The App

    Each User can have multiple states. The State simply represents their current session.

    Columns:
        id: The primary key. This is sent to the browser as a cookie to identify across requests
        user_id: Pretty self explanatory. Holds the identifier for the user if they are logged in.
        __current_card_seed: The initial seed for the randomness to shuffle the cards - private variable
        __current_card_iter: The current card of the shuffled set. (zero indexed) - private variable
        score: The score of the current user
    """
    __tablename__ = "state"
    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, default=None)
    user = db.relationship('User', uselist=False)
    __current_card_seed = db.Column(db.Integer, nullable=False)
    __current_card_iter = db.Column(db.Integer, nullable=True, default=None)
    score = db.Column(db.Integer, default=0)

    def __init__(self):
        self.id = self.generate_id()
        self.__current_card_seed = datetime.datetime.now().microsecond

    @hybrid_property
    def card(self) -> Optional['Card']:
        """Return The Currently Selected Card

        Uses the states seed to ensure that the same card is received
        """

        random.seed(self.__current_card_seed)
        card_order = random.sample(self.user.cards, len(self.user.cards))
        if self.__current_card_iter is None:
            return None
        else:
            return card_order[self.__current_card_iter]

    def next_card(self) -> 'Card':
        """Change To The Next Card"""
        if self.__current_card_iter is None or self.__current_card_iter + 1 >= len(self.user.cards):
            # Generate new seed
            if self.__current_card_iter is not None:
                self.__current_card_seed = datetime.datetime.now().microsecond
            self.__current_card_iter = 0
        else:
            self.__current_card_iter += 1
        db.session.commit()
        return self.card

    def reset_card(self) -> None:
        """Sets The Iter To None"""
        self.__current_card_iter = None

    @staticmethod
    def generate_id() -> str:
        """Generates A Random ID"""
        while True:
            potential_id = hashlib.sha256(os.urandom(128)).hexdigest()
            if not State.id_exists(potential_id):
                return potential_id


class School(db.Model, CommonModelMixin):
    """Represents A School

    Columns:
        id: Primary key
        name: Name of the school
    """
    __tablename__ = "school"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    students = db.relationship('User', back_populates="school")

    def __init__(self, name: str):
        self.name = name


class User(db.Model, CommonModelMixin):
    """Represents a User

    Columns:
        id: Primary key
        school_id: Identifies the School the user is associated with
        username: The name of the user
        __password: The password stored as a bcrypt hash - private variable
        salt: The salt used to hash the password
        highscore: The users best score

    Notes:
        There isn't a constraint on individual usernames. There may be two users
        named "jackson" as long as they are from different schools.
    """
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    cards = db.relationship('Card')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)
    school = db.relationship('School', back_populates="students")
    state = db.relationship('State', back_populates="user")
    username = db.Column(db.String(20), nullable=False)
    __password = db.Column(db.LargeBinary(60), nullable=False)
    salt = db.Column(db.String(24), nullable=False)
    highscore = db.Column(db.Integer, default=None)

    db.UniqueConstraint('username', 'school')  # Create A Composite Constraint

    def __init__(self, username: str, password: str, school: School):
        self.salt = self.generate_salt()
        self.username = username
        self.password = password
        self.school = school

    @hybrid_property
    def password(self) -> str:
        """This enables abstraction away from the private variable __password

        This is a getter property that is integrated in the database as a hybrid_property, which allows
        it to be executed by the database as well as the application
        """
        return self.__password

    @password.setter
    def password(self, plain_password: str) -> None:
        """Enables Super Simple And Safe Password Saving

        Instead of hashing the password manually each time it needs to be changed,
        this function allows us to simply specify `User.password = "newpassword"`.
        And the password will be converted and saved appropriately.

        Defines the setter for the hybrid_property `password`
        """
        salted_password = plain_password + self.salt
        self.__password = bcrypt.generate_password_hash(salted_password, rounds=app.config['BCRYPT_LOG_ROUNDS'])

    @hybrid_method
    def check_password(self, plain_password: str) -> bool:
        """Checks If The User Entered The Right Password"""
        salted_password = plain_password + self.salt
        return bcrypt.check_password_hash(self.password, salted_password)

    @staticmethod
    def generate_salt():
        """Generates a salt for use in hashing the password"""
        return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode()


class Card(db.Model, CommonModelMixin):
    """Represents A User's Card

    Columns:
        id: Primary key
        user_id: Identifies the User that the Card is associated with
        question: The question on the card
        answer: The answer on the card
    """
    __tablename__ = "card"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    question = db.Column(db.String(30), nullable=False)
    answer = db.Column(db.String(30), nullable=False)

    def __init__(self, user: User, question: str, answer: str):
        self.user = user
        self.question = question.strip()  # Get rid of whitespace on either side of the text
        self.answer = answer.strip()  # Same as above

    def render(self) -> str:
        """Returns a html string that is displayed in the game

        This is probably not xss safe but eh, it is a *basic* math game
        """
        return "<div class='container'>" \
               "<div class='title'>" \
               "<h1 class='item-text'>{q}</h1>" \
               "</div>" \
               "<div class='delete'>" \
               "<img src='{del_img}' alt='Delete' onclick='deleteCard(this);' data-id={id}>" \
               "</div></div>".format(q=self.question,
                                     a=self.answer,
                                     del_img=flask.url_for('static', filename='delete.svg'),
                                     id=self.id)


##########
# FORMS #
#########

class LoginForm(flask_wtf.FlaskForm):
    """The Form That Is Displayed When The User Attempts To Login"""
    username = wtforms.StringField("Username", validators=[
        wtforms.validators.DataRequired()
    ])
    password = wtforms.PasswordField("Password", validators=[
        wtforms.validators.DataRequired()
    ])
    school = QuerySelectField('School', query_factory=lambda: School.query.order_by('name').all(), get_label='name',
                              get_pk=lambda a: a.id, validators=[
            wtforms.validators.DataRequired()
        ])
    user = None

    def validate(self) -> bool:
        """Validates All Submitted Data"""
        if not flask_wtf.FlaskForm.validate(self):
            return False
        else:
            user = User.query.filter_by(username=self.username.data, school_id=self.school.data.id).first()
            if user is None:  # User doesn't exist
                self.username.errors.append("Incorrect Username Or Password")
                return False
            elif not user.check_password(self.password.data):  # Password Incorrect
                self.username.errors.append("Incorrect Username Or Password")
                return False
            else:  # Password Correct!
                self.user = user
                return True


# noinspection PyUnusedLocal
class RegisterForm(flask_wtf.FlaskForm):
    """The Form Displayed When The User Registers An Account"""
    username = wtforms.StringField("Username", validators=[
        wtforms.validators.DataRequired(),
        wtforms.validators.Length(max=20)
    ])
    password = wtforms.PasswordField("Password", validators=[
        wtforms.validators.DataRequired()
    ])
    confirm_password = wtforms.PasswordField("Confirm Password", validators=[
        wtforms.validators.EqualTo('password', message="Passwords Do Not Match")
    ])
    school = QuerySelectField('School',
                              query_factory=lambda: School.query.order_by('name').all(),
                              get_label='name', allow_blank=False, get_pk=lambda a: a.id,
                              validators=[wtforms.validators.DataRequired()])

    @staticmethod
    def validate_username(form: flask_wtf.FlaskForm, username_field: wtforms.StringField):
        """Validates That The Username Is Available"""
        if User.query.filter_by(username=username_field.data, school=form.school.data).first() is not None:
            raise wtforms.validators.ValidationError("Username Taken")


###########
# ROUTING #
###########

@app.route('/', methods=('GET',))
@state_handler
def index(state: State) -> flask.Response:
    """Index Page. Nothing Special Here

    If user is logged in redirect to cards route
    """
    if state.user is not None:
        return flask.redirect('/cards')
    else:
        return flask.render_template('index.jinja')


@app.route('/login', methods=('GET', 'POST'))
@state_handler
def login(state: State) -> flask.Response:
    """Login Page"""
    if state.user is not None:
        return flask.redirect('/cards')  # If user is already logged in - Redirect to /cards
    form = LoginForm()  # Create a form
    if form.validate_on_submit():  # If Form has been submitted and is valid
        user = User.query.filter_by(username=form.username.data, school=form.school.data).first()
        state.user = user  # Update User i.e. Authenticate
        db.session.commit()
        return flask.redirect('/cards')  # Redirect to /cards
    else:
        return flask.render_template('login.jinja', form=form)  # If GET and not logged in


@app.route('/register', methods=('GET', 'POST'))
@state_handler
def register(state: State) -> flask.Response:
    """Register Page"""
    if state.user is not None:
        return flask.redirect('/cards')  # If user is already logged in - Redirect to /cards
    form = RegisterForm()  # Create a form
    if form.validate_on_submit():  # If Form has been submitted and is valid
        user = User(form.username.data, form.password.data, form.school.data)  # Create a new user
        db.session.add(user)
        state.user = user  # Update the state to use this user i.e. Authenticate
        db.session.commit()
        return flask.redirect('/cards')  # Redirect to /cards
    else:
        return flask.render_template('register.jinja', form=form)


@app.route('/logout', methods=('GET',))
@state_handler
def logout(state: State) -> flask.Response:
    """Pretty Basic Logging Out"""
    state.user = None
    db.session.commit()
    return flask.redirect('/', 302)


@app.route('/cards', methods=('GET',))
@state_handler
@require_login
def cards(state: State) -> flask.Response:
    """Cards View"""
    return flask.render_template("cards.jinja", user=state.user)


@app.route('/play', methods=('GET',))
@state_handler
@require_login
def play(state: State) -> flask.Response:
    """The Actual Game"""
    if len(state.user.cards) == 0:  # If there are no cards
        flask.abort(400)
    state.score = 0  # Reset Score
    state.reset_card()  # Reset how many iterations have been played
    db.session.commit()
    return flask.render_template('game.jinja', state=state)


@app.route('/api/add_card', methods=('POST',))
@state_handler
@require_login
def add_card_api(state: State) -> flask.Response:
    """Adds A Card To Logged On User

    This route is intended for use by xhr/ajax

    POST Parameters:
        q: The question that should be on the card
        a: The answer to the question

    Returns: The HTML of the requested card
    """
    # Get variables
    q = flask.request.form['q']
    a = flask.request.form['a']

    card = Card(state.user, q, a)  # Create card
    db.session.add(card)
    db.session.commit()
    return flask.make_response(card.render(), 201)  # Return html of card


@app.route('/api/remove_card', methods=('POST',))
@state_handler
@require_login
def remove_card_api(state: State) -> flask.Response:
    """Removes A Card From Logged On User

    This route is intended for use by xhr/ajax

    POST Parameters:
        id: The id of the Card to remove

    Returns:
        200: Success
        403: You tried to delete someone else's card. SAD!
    """
    card = Card.query.get(flask.request.form['id'])
    if card is not None and card in state.user.cards:
        db.session.delete(card)  # Delete card
        db.session.commit()
        return flask.make_response('success', 200)
    else:
        flask.abort(403)


@app.route('/api/get_card', methods=('GET',))
@state_handler
@require_login
def get_card_api(state: State) -> flask.Response:
    """Gets The Currently Selected Card For User

    This route is intended for use by xhr/ajax

    GET Parameters:
        n: Whether to fetch the next card. If n!=1: Use Current Card
           Default: 0

    Returns: JSON
        {
            "id": card.id,
            "question": card.question
        }
    """
    if int(flask.request.args.get('n', 0)):  # Whether to fetch the next card
        if len(state.user.cards) == 0:  # No Cards
            return flask.make_response('', 204)
        else:
            card = state.next_card()  # Get next card
    else:  # Do not fetch next card
        if state.card is None:
            return flask.make_response('', 204)
        card = state.card
    return flask.jsonify(dict(id=card.id, question=card.question))


@app.route('/api/answer_card', methods=('POST',))
@state_handler
@require_login
def answer_card_api(state: State) -> flask.Response:
    """Verify A User's Answer

    This route is intended for use by xhr/ajax

    POST Parameters:
        a: The answer to test against

    Returns:
        JSON with the fields:
            correct (bool): indicates whether the answer was correct
            score (int): The current score of the User
        if correct is False the following fields will also be included:
            answer (str): The correct answer
            highscore (int): The highscore of the User
    """
    answer = flask.request.form['a']  # Get the user-submitted answer
    answer_formatted = answer.lower().strip()  # Normalise the answer
    if state.card is None:
        flask.abort(400)
    if answer_formatted == state.card.answer.lower():  # If user was correct
        state.score += 1
        state.next_card()
        db.session.commit()
        return flask.jsonify({
            "correct": True,
            "score": state.score
        })
    else:  # If user was incorrect
        payload = {
            "correct": False,
            "score": state.score,
            "answer": state.card.answer,
            "highscore": state.user.highscore,
        }
        if state.user.highscore is None or state.score > state.user.highscore:  # If it is a new highscore
            state.user.highscore = state.score  # Update highscore
            db.session.commit()
        return flask.jsonify(payload)


# If run directly
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)  # Run app using dev server
