function formatQuestion(modal){
    modal.getElementsByClassName('swal2-input')[0].oninput = function () {
        this.value = this.value.replace(/\*/g, '×');
        this.value = this.value.replace(/\//g, '÷');
    };
}

function validateAnswer(q, a){
    return new Promise(function(resolve, reject){
        let xhr = new XMLHttpRequest();
        xhr.open("POST", "api/add_card", true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    resolve(xhr.responseText);
                } else {
                    reject();
                }
            }
        };
        xhr.send('q='+encodeURIComponent(q)+'&a='+encodeURIComponent(a));
    })
}

function addCardPrompt() {
    swal.setDefaults({
        progressSteps: ['1', '2'],
        customClass: 'prompt'
    });
    let steps = [
        {
            titleText: 'Question',
            inputPlaceholder: "enter your question here",
            type: 'question',
            input: 'text',
            showCancelButton: true,
            onOpen: formatQuestion
        },
        {
            titleText: 'Answer',
            type: 'question',
            input: 'text',
            showCancelButton: true,
        }
    ];
    swal.queue(steps).then(function (value) {
        swal.resetDefaults();
        swal({
            titleText: "Processing...",
            allowOutsideClick: false,
            onOpen: () => {swal.showLoading();}
        });
        return validateAnswer(value.value[0], value.value[1]);
    }).then(function (value) {
        swal.close();
        swal({
            titleText: "Success",
            type: 'success',
            timer: 5000
        });
        console.log({message:'succeeded', value:value});
        let el = document.createElement('div');
        el.innerHTML = value;
        el.className = 'item';
        document.getElementById('grid-container').insertBefore(el, document.getElementById('add-card'));
    }).catch(function (value) {
        swal.close();
        swal({
            titleText: "Error",
            type: 'error',
            timer: 5000
        });
        console.log({message: 'failed', value: value});
    })
}

function deleteCard(card) {
    let id = card.dataset.id;
    swal({
        titleText: "Deleting...",
        allowOutsideClick: false,
        onOpen: () => {
            swal.showLoading();
        }
    });

    let xhr = new XMLHttpRequest();
    xhr.open("POST", "api/remove_card", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4) {
            swal.close();
            if (xhr.status === 200) {
                document.getElementById('grid-container').removeChild(card.parentElement.parentElement.parentElement);
                swal({
                    titleText: "Success",
                    type: 'success',
                    timer: 5000
                });
            } else {
                swal({
                    titleText: "Error",
                    type: 'error',
                    timer: 5000
                });
            }
        }
    };
    xhr.send('id='+id);
}
