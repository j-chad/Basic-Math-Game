function formatQuestion(modal){
    modal.getElementsByClassName('swal2-input')[0].oninput = function () {
        this.value = this.value.replace(/\*/g, '×');
        this.value = this.value.replace(/\//g, '÷');
    };
}

function validateAnswer(value){
    return new Promise(function(resolve){
        console.log(value);
    });
}

function addCardPrompt() {
    swal.setDefaults({
        progressSteps: ['1', '2'],
        customClass: 'prompt'
    });
    var steps = [
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
            type: 'info',
            input: 'text',
            showCancelButton: true
        }
    ];
    swal.queue(steps).then(function (value) {
        console.log(value);
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "api/add_card", true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    var el = document.createElement('div');
                    el.innerHTML = xhr.responseText;
                    el.className = 'item';
                    document.getElementById('grid-container').insertBefore(el, document.getElementById('add-card'));
                }
            }
        }
        xhr.send('q='+value.value[0]+'&a='+value.value[1])
    });
}

