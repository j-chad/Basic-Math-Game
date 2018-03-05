function get_card(n){
    n = n ? "1" : "0";
    return new Promise(function (resolve, reject) {
        let xhr = new XMLHttpRequest();
        xhr.open("GET", "api/get_card?n="+n, true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        xhr.onreadystatechange = function(){
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    resolve(JSON.parse(xhr.responseText));
                } else {
                    reject();
                }
            }
        };
        xhr.send();
    });
}

function apply_card(value){
    let title = document.getElementById('card-title');
    let button = document.getElementById('card-submit');
    /** @namespace value.question */
    title.innerText = value.question;
    button.dataset.id = value.id;
    button.disabled = false;
    document.getElementById('card-answer').value = "";
}

function submit(){
    let answer = document.getElementById('card-answer').value;
    document.getElementById('card-submit').disabled = true; //Disable Button
    swal({
        titleText: "Submitting...",
        allowOutsideClick: false,
        onOpen: () => {
            swal.showLoading();
        }
    });
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "api/answer_card", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4) {
            swal.close();
            if (xhr.status === 200) {
                let response = JSON.parse(xhr.responseText);
                console.log(response);
                /** @namespace response.correct */
                if (response.correct){
                    get_card(1).then(apply_card);
                    /** @namespace response.score */
                    document.getElementById('score').innerText = response.score;
                    swal({
                        titleText: "Correct!",
                        type: "success",
                        timer: 2000
                    })
                } else {
                    let text;
                    /** @namespace response.highscore */
                    if(response.highscore == null){
                        text = `New Highscore!`;
                    }else if(response.score > response.highscore){
                        text = `New Highscore! (${response.score} > ${response.highscore})`;
                    } else {
                        text = `You were ${response.highscore - response.score} points away from your highscore!`;
                    }
                    swal({
                        titleText: "Not Quite",
                        text: text,
                        type: "error",
                    }).then(() => {
                        window.location = '/cards';
                    });
                }
            } else {
                swal({
                    titleText: "Error",
                    text: "Something went wrong...",
                    type: "error",
                    timer: 2500
                });
            }
        }
    };
    xhr.send("a=" + answer);
}


document.addEventListener('DOMContentLoaded', function () {
    swal({
        titleText: "Loading...",
        allowOutsideClick: false,
        onOpen: () => {
            swal.showLoading();
        }
    });
    get_card(1).then(function(value){
        swal.close();
        apply_card(value);
    }).catch(function () {
        swal.close();
        swal({
            titleText: "Error",
            text: "Something went wrong...",
            type: "error",
            timer: 2500
        });
    });
});

document.addEventListener("keyup", event => {
    if (event.key === "Enter"
        && !swal.isVisible()
        && document.getElementById('card-answer') === document.activeElement) submit();
});