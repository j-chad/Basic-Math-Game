ECHO off
TITLE Basic-Math-Game Installer


cd Basic-Math-Game

pip3 install --user virtualenv
virtualenv Env
Env\Scripts\pip install -r requirements.txt

set FLASK_APP=main.py
flask init
flask run
start http://localhost:8080
