# Basic Math Game

Tested on Python 3.6

This is a **very** basic flashcard web game.

It was made for 
[AS91637](http://www.nzqa.govt.nz/ncea/assessment/view-detailed.do?standardNumber=91633) & 
[AS91633](http://www.nzqa.govt.nz/ncea/assessment/view-detailed.do?standardNumber=91637)

##How To Run
This tutorial is for windows only

Alternatively you can download [this]() script which does everything automatically.

1. Pull this repository
    ```cmd
    git clone https://github.com/j-chad/Basic-Math-Game.git
    cd Basic-Math-Game
    ```
2. Install all requirements. This should be done inside of a virtual env.
    ```cmd
    pip install -r requirements.txt    
    ```
3. Initialise the app
    ```cmd
    set FLASK_APP=main.py
    flask init
    flask run
    ```
4. Open your browser to: [`http://localhost:8080`](http://localhost:8080)
