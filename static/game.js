function get_card(n){
    n = n ? "1" : "0";
    return new Promise(function (resolve, reject) {
        let a = swal({
            titleText: "Loading...",
            allowOutsideClick: false,
            onOpen: () => {swal.showLoading();}
        });
        let xhr = new XMLHttpRequest();
        xhr.open("GET", "api/get_card?n="+n, true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        xhr.onreadystatechange = function(){
            if (xhr.readyState === 4) {
                swal.close();
                if (xhr.status === 200) {
                    resolve(JSON.parse(xhr.responseText));
                } else {
                    swal({
                        titleText: "Error",
                        text: "Something went wrong...",
                        type: "error",
                        timer: 2500
                    });
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
}

function submit(){

}


document.addEventListener('DOMContentLoaded', function () {
    get_card(1).then(apply_card);
});