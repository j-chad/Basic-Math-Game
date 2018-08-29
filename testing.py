import flask
import flask_testing
from werkzeug.datastructures import Headers
from werkzeug.exceptions import Forbidden

import main


class BaseTestCase(flask_testing.TestCase):

    def create_app(self):
        app = main.app
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
        app.config["BCRYPT_LOG_ROUNDS"] = 5
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["TESTING"] = True
        return app

    def setUp(self):
        main.db.create_all()
        schools = (
            "Sancta Maria College",
            "Sancta Maria Primary"
        )
        for i in schools:
            main.db.session.add(main.School(i))
        main.db.session.commit()

    def tearDown(self):
        main.db.session.remove()
        main.db.drop_all()


# @unittest.skip
class RegisterAndLogInTest(BaseTestCase):
    """Tests all methods related to registering and logging in"""

    def test_register_form_success(self):
        form = main.RegisterForm(username="myusername",
                                 password="bestpasswordeverliterallyunhackable",
                                 confirm_password="bestpasswordeverliterallyunhackable",
                                 school=main.School.query.get(1))
        self.assertTrue(form.validate())

    def test_register_form_username_blank(self):
        form = main.RegisterForm(username="",
                                 password="bestpasswordeverliterallyunhackable",
                                 confirm_password="bestpasswordeverliterallyunhackable",
                                 school=main.School.query.get(1))
        self.assertFalse(form.validate())

    def test_register_form_username_too_long(self):
        form = main.RegisterForm(username="thisusernameismorethan20characters",
                                 password="bestpasswordeverliterallyunhackable",
                                 confirm_password="bestpasswordeverliterallyunhackable",
                                 school=main.School.query.get(1))
        self.assertFalse(form.validate())

    def test_register_form_username_exact(self):
        form = main.RegisterForm(username="myusernameisquitebig",
                                 password="bestpasswordeverliterallyunhackable",
                                 confirm_password="bestpasswordeverliterallyunhackable",
                                 school=main.School.query.get(1))
        self.assertTrue(form.validate())

    def test_register_form_password_blank(self):
        form = main.RegisterForm(username="12345678901",
                                 password="",
                                 confirm_password="",
                                 school=main.School.query.get(1))
        self.assertFalse(form.validate())

    def test_register_form_passwords_dont_match(self):
        form = main.RegisterForm(username="12345678901",
                                 password="worstpasswordevercompletelyhackable",
                                 confirm_password="bestpasswordeverliterallyunhackable",
                                 school=main.School.query.get(1))
        self.assertFalse(form.validate())

    def test_register_form_username_taken_same_school(self):
        main.db.session.add(main.User('myusername', 'greatpassword', main.School.query.get(1)))
        main.db.session.commit()
        form = main.RegisterForm(username="myusername",
                                 password="bestpasswordeverliterallyunhackable",
                                 confirm_password="bestpasswordeverliterallyunhackable",
                                 school=main.School.query.get(1))
        self.assertFalse(form.validate())

    def test_register_get(self):
        self.assert200(self.client.get(flask.url_for('register')))

    def test_register_success(self):
        response = self.client.post(flask.url_for('register'), data={
            'username'        : "myusername",
            'password'        : "bestpasswordeverliterallyunhackable",
            'confirm_password': "bestpasswordeverliterallyunhackable",
            'school'          : '1'
        })
        with self.subTest("redirects"):
            self.assertRedirects(response, flask.url_for('cards'))
        with self.subTest("creates user"):
            self.assertEqual(main.User.query.filter_by(
                username="myusername",
                school=main.School.query.get(1)
            ).count(), 1)
        with self.subTest("changes state"):
            state = self.client.cookie_jar._cookies['localhost.local']['/']['game-state'].value
            state_obj = main.State.query.get(state)
            self.assertIsNotNone(state_obj)
            self.assertIsNotNone(state_obj.user)

    def test_register_already_logged_in_redirects(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        state_obj.user = user_obj
        main.db.session.add_all((state_obj, user_obj))
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('register'))
        self.assertRedirects(response, flask.url_for('cards'))

    def test_login_form_success(self):
        main.db.session.add(main.User(username="myusername",
                                      password="bestpasswordeverliterallyunhackable",
                                      school=main.School.query.get(1)))
        form = main.LoginForm(username="myusername",
                              password="bestpasswordeverliterallyunhackable",
                              school=main.School.query.get(1))
        with self.subTest("validates"):
            self.assertTrue(form.validate())
        with self.subTest("returns user"):
            self.assertIsInstance(form.user, main.User)

    def test_login_form_fail_username(self):
        main.db.session.add(main.User(username="myusername",
                                      password="bestpasswordeverliterallyunhackable",
                                      school=main.School.query.get(1)))
        form = main.LoginForm(username="notmyusername",
                              password="bestpasswordeverliterallyunhackable",
                              school=main.School.query.get(1))
        with self.subTest("doesn't validates"):
            self.assertFalse(form.validate())
        with self.subTest("doesn't apply user"):
            self.assertIsNone(form.user)

    def test_login_form_fail_password(self):
        main.db.session.add(main.User(username="myusername",
                                      password="bestpasswordeverliterallyunhackable",
                                      school=main.School.query.get(1)))
        form = main.LoginForm(username="myusername",
                              password="worstpasswordevercompletelyhackable",
                              school=main.School.query.get(1))
        with self.subTest("doesn't validates"):
            self.assertFalse(form.validate())
        with self.subTest("doesn't apply user"):
            self.assertIsNone(form.user)

    def test_login_form_fail_school(self):
        main.db.session.add(main.User(username="myusername",
                                      password="bestpasswordeverliterallyunhackable",
                                      school=main.School.query.get(1)))
        form = main.LoginForm(username="myusername",
                              password="bestpasswordeverliterallyunhackable",
                              school=main.School.query.get(2))
        with self.subTest("doesn't validates"):
            self.assertFalse(form.validate())
        with self.subTest("doesn't apply user"):
            self.assertIsNone(form.user)

    def test_login_get(self):
        self.assert200(self.client.get(flask.url_for('login')))

    def test_login_success(self):
        main.db.session.add(main.User(username="myusername",
                                      password="bestpasswordeverliterallyunhackable",
                                      school=main.School.query.get(1)))
        main.db.session.commit()
        response = self.client.post(flask.url_for('login'), data={
            'username': "myusername",
            'password': "bestpasswordeverliterallyunhackable",
            'school'  : '1'
        })
        with self.subTest("redirects"):
            self.assertRedirects(response, flask.url_for('cards'))
        with self.subTest("changes state"):
            state = self.client.cookie_jar._cookies['localhost.local']['/']['game-state'].value
            state_obj = main.State.query.get(state)
            self.assertIsNotNone(state_obj)
            self.assertIsNotNone(state_obj.user)

    def test_login_already_logged_in_redirects(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        state_obj.user = user_obj
        main.db.session.add_all((state_obj, user_obj))
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('login'))
        self.assertRedirects(response, flask.url_for('cards'))

    def test_logout_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        state_obj.user = user_obj
        main.db.session.add_all((state_obj, user_obj))
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('logout'))
        self.assertRedirects(response, flask.url_for('index'))
        self.assertIsNone(state_obj.user)


# @unittest.skip
class UnexposedMethodsTesting(BaseTestCase):
    """Tests all methods that are not directly exposed to the user"""

    def test_state_handler_existing_state(self):
        state_obj = main.State()
        main.db.session.add(state_obj)
        main.db.session.commit()

        @main.state_handler
        def func(state):
            self.assertIs(state, state_obj)
            return '', 200

        with self.app.test_request_context(headers=Headers([('Cookie', 'game-state={};'.format(state_obj.id))])):
            response = func()
            self.assertIn("game-state={}".format(state_obj.id), response.headers['set-cookie'])

    def test_state_handler_none_state(self):
        @main.state_handler
        def func(state: main.State) -> flask.Response:
            self.assertIsNotNone(state)
            self.assertIsNone(state.user)
            return flask.make_response(state.id, 200)

        with self.app.test_request_context():
            func()

    def test_state_handler_invalid_state(self):

        state_id = main.State.generate_id()

        @main.state_handler
        def func(state: main.State) -> flask.Response:
            self.assertNotEqual(state.id, state_id)
            self.assertIsNone(state.user)
            return flask.make_response(state.id, 200)

        with self.app.test_request_context(headers=Headers([('Cookie', 'game-state={};'.format(state_id))])):
            func()

    def test_require_login_success(self):
        state_obj = main.State()
        main.db.session.add(state_obj)

        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add(user_obj)

        state_obj.user = user_obj
        main.db.session.commit()

        @main.state_handler
        @main.require_login
        def func(state):
            with self.subTest("test_state_passed"):
                self.assertIs(state, state_obj)
            self.assertIsNotNone(state.user)
            return '', 200

        with self.app.test_request_context(headers=Headers([('Cookie', 'game-state={};'.format(state_obj.id))])):
            response = func()
            with self.subTest('test_state_passed_through'):
                self.assertIn("game-state={}".format(state_obj.id), response.headers['set-cookie'])
            self.assert200(response)

    def test_require_login_fail(self):
        state_obj = main.State()
        main.db.session.add(state_obj)
        main.db.session.commit()

        @main.state_handler
        @main.require_login
        def func(state):
            self.fail('app didn\'t abort')

        with self.app.test_request_context(headers=Headers([('Cookie', 'game-state={};'.format(state_obj.id))])):
            try:
                func()
            except Forbidden:
                pass
            else:
                self.fail('did not raise Forbidden')


# @unittest.skip
class ModelTesting(BaseTestCase):
    """Tests All Methods Related To The Database"""

    def test_state_card(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))

        state_obj.user = user_obj
        state_obj._State__current_card_seed = 259720  # [2, 3, 4, 1]
        main.db.session.add(main.Card(state_obj.user, "card 1", "1"))
        card_2 = main.Card(state_obj.user, "card 2", "2")
        main.db.session.add(card_2)
        main.db.session.add(main.Card(state_obj.user, "card 3", "3"))
        main.db.session.add(main.Card(state_obj.user, "card 4", "4"))

        main.db.session.commit()

        self.assertIs(state_obj.next_card(), card_2)
        self.assertIsNotNone(state_obj._State__current_card_iter)
        self.assertIs(state_obj.card, card_2)

    def test_user_check_password_true(self):
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add(user_obj)
        main.db.session.commit()

        self.assertTrue(user_obj.check_password("mypassword"))

    def test_user_check_password_false(self):
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add(user_obj)
        main.db.session.commit()

        self.assertFalse(user_obj.check_password("notmypassword"))


# @unittest.skip
class ViewTesting(BaseTestCase):
    """Tests all views that are exposed to the user"""

    def test_index_not_logged_in_no_redirect(self):
        self.assert200(self.client.get(flask.url_for('index')))

    def test_index_logged_in_redirect(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        state_obj.user = user_obj
        main.db.session.add_all((state_obj, user_obj))
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('index'))
        self.assertRedirects(response, flask.url_for('cards'))

    def test_cards_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('cards'))
        self.assert200(response)

    def test_play_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj,
                                 main.Card(user_obj, "q1", "a1"),
                                 main.Card(user_obj, "q2", "a2")))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('play'))
        self.assert200(response)

    def test_play_empty(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('play'))
        self.assert400(response)


class APITesting(BaseTestCase):
    """Testing for methods exposed to the user in the form of a REST API"""

    def test_add_card_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('add_card_api'), data={
                "q": "q1",
                "a": "a1"
            })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(main.Card.query.filter_by(user=user_obj).count(), 1)

    def test_add_card_missing_arg_q_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('add_card_api'), data={"a": "a1"})
        self.assert400(response)

    def test_add_card_missing_arg_a_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('add_card_api'), data={"q": "q1"})
        self.assert400(response)

    def test_add_card_missing_args_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('add_card_api'), data={})
        self.assert400(response)

    def test_add_card_get_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('add_card_api'), data={
                "q": "q1",
                "a": "a1"
            })
        self.assertEqual(response.status_code, 405)

    def test_remove_card_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        card_obj = main.Card(user_obj, 'q1', 'a1')
        main.db.session.add_all((state_obj, user_obj, card_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('remove_card_api'), data={"id": card_obj.id})
        self.assert200(response)
        self.assertEqual(main.Card.query.filter_by(user=user_obj).count(), 0)

    def test_remove_card_no_id_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('remove_card_api'), data={})
        self.assert400(response)

    def test_remove_card_invalid_id_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        card_obj = main.Card(user_obj, 'q1', 'a1')
        main.db.session.add_all((state_obj, user_obj, card_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('remove_card_api'), data={'id': card_obj.id + 1})
        self.assert403(response)
        self.assertEqual(main.Card.query.filter_by(user=user_obj).count(), 1)

    def test_remove_card_get_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        card_obj = main.Card(user_obj, 'q1', 'a1')
        main.db.session.add_all((state_obj, user_obj, card_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('remove_card_api'), data={'id': card_obj.id})
        self.assert405(response)
        self.assertEqual(main.Card.query.filter_by(user=user_obj).count(), 1)

    def test_get_card_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((
            state_obj,
            user_obj,
            main.Card(user_obj, 'q1', 'a1'),
            main.Card(user_obj, 'q2', 'a2'),
        ))
        card_obj_1 = main.Card(user_obj, 'q3', 'a3')
        card_obj_2 = main.Card(user_obj, 'q4', 'a4')
        main.db.session.add_all((
            card_obj_1,
            card_obj_2,
            main.Card(user_obj, 'q5', 'a5')
        ))
        state_obj.user = user_obj
        state_obj._State__current_card_seed = 608731  # [3, 4, 5, 2, 1]
        main.db.session.commit()
        print(card_obj_1.id, card_obj_2.id)

        with self.subTest('get first card'):
            with self.client as c:
                c.set_cookie('localhost', 'game-state', state_obj.id)
                response = c.get(flask.url_for('get_card_api', n=1))
                self.assert200(response)
                self.assertEqual(response.json['id'], card_obj_1.id)

        with self.subTest('get current card'):
            with self.client as c:
                c.set_cookie('localhost', 'game-state', state_obj.id)
                response = c.get(flask.url_for('get_card_api', n=0))
                self.assert200(response)
                self.assertEqual(response.json['id'], card_obj_1.id)

        with self.subTest('get next card'):
            with self.client as c:
                c.set_cookie('localhost', 'game-state', state_obj.id)
                response = c.get(flask.url_for('get_card_api', n=1))
                self.assert200(response)
                self.assertEqual(response.json['id'], card_obj_2.id)

        with self.subTest('get current card (next)'):
            with self.client as c:
                c.set_cookie('localhost', 'game-state', state_obj.id)
                response = c.get(flask.url_for('get_card_api', n=0))
                self.assert200(response)
                self.assertEqual(response.json['id'], card_obj_2.id)

        with self.subTest('overflow iterator'):
            state_obj._State__current_card_iter = 5
            main.db.session.commit()
            with self.client as c:
                c.set_cookie('localhost', 'game-state', state_obj.id)
                response = c.get(flask.url_for('get_card_api', n=1))
                self.assert200(response)
                self.assertIn(response.json['id'], [i.id for i in main.Card.query.all()])

    def test_get_card_no_cards_fail(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('get_card_api') + '?n=1')
            self.assertEqual(response.status_code, 204)

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.get(flask.url_for('get_card_api') + '?n=0')
            self.assertEqual(response.status_code, 204)

    def test_answer_card_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        card_obj = main.Card(user_obj, 'q1', 'a1')
        main.db.session.add_all((state_obj, user_obj, card_obj))
        state_obj.user = user_obj
        state_obj._State__current_card_iter = 0
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('answer_card_api'), data={'a': 'a1'})
            self.assert200(response)
            self.assertTrue(response.json['correct'])
            self.assertIn('score', response.json)

    def test_answer_card_incorrect_success(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        card_obj = main.Card(user_obj, 'q1', 'a1')
        main.db.session.add_all((state_obj, user_obj, card_obj))
        state_obj.user = user_obj
        state_obj._State__current_card_iter = 0
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('answer_card_api'), data={'a': 'a2'})
            self.assert200(response)
            self.assertFalse(response.json['correct'])
            self.assertIn('score', response.json)
            self.assertEqual(response.json['answer'], 'a1')
            self.assertIn('highscore', response.json)

    def test_answer_missing_arg(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        card_obj = main.Card(user_obj, 'q1', 'a1')
        main.db.session.add_all((state_obj, user_obj, card_obj))
        state_obj.user = user_obj
        state_obj._State__current_card_iter = 0
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('answer_card_api'))
            self.assert400(response)

    def test_answer_no_cards(self):
        state_obj = main.State()
        user_obj = main.User("myusername", "mypassword", main.School.query.get(1))
        main.db.session.add_all((state_obj, user_obj))
        state_obj.user = user_obj
        main.db.session.commit()

        with self.client as c:
            c.set_cookie('localhost', 'game-state', state_obj.id)
            response = c.post(flask.url_for('answer_card_api'), data={'a': "a1"})
            self.assert400(response)
