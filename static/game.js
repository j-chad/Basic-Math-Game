function get_card(){
    return new Promise(function (resolve, reject) {
        let xhr = new XMLHttpRequest();
        xhr.open("POST", "api/get_card", true);
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
        xhr.send('q=' + encodeURIComponent(q) + '&a=' + encodeURIComponent(a));
    });
}

$(document).ready(function(){
    get_card().then(function (value) {
        console.log(value);
    }).catch(function () {
        // Oh No
    })
});