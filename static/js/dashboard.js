var i = 0;
function move(sec) {
    if (i == 0) {
        i = 1;
        var elem = document.getElementById("bar");
        var width = 0;
        var id = setInterval(frame, 10);
        function frame() {
            if (width >= 100) {
                clearInterval(id);
                i = 0;
            } else {
                width = width + 1.6/sec;
                elem.style.width = width + "%";
            }
        }
    }
}
move(10)
function login () {
    location.href = '/';
}
setTimeout(login, 10500);
