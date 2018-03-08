ECHO off
TITLE Basic-Math-Game Installer

git clone https://github.com/j-chad/Basic-Math-Game.git
cd Basic-Math-Game

pip3 install --user virtualenv
virtualenv Env
Env\Scripts\pip install -r requirements.txt

set FLASK_APP=main.py
flask init
flask run
start http://localhost:8080