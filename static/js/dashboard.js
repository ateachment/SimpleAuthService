// add evemt listener 
document.addEventListener('click', function (e) {
    if (e.target.id === "registerPasskeyBtn") {
        registerPasskey();
        return;
    }
    if(e.target.href != undefined) {  // but add only to links, not to button!
        e.preventDefault();
    loadContent(e.target.href);
    }
});

// function to handle passkey registration flow
async function registerPasskey() {

    const response = await fetch("/passkey/register/begin", {
        method: "POST",
        headers: {
            "Authorization": "Bearer " + token
        }
    });

    const options = await response.json();

    const credential = await navigator.credentials.create({
        publicKey: options
    });

    console.log(credential);
}


var timeoutID = setTimeout(logout, 10500);

function loadContent (page) {
    fetch(page)
   
    .then((result) => {
      if (result.status != 200) { throw new Error("Bad Server Response"); }
      return result.text();
    })
   
    // put loaded content into <div
    .then((content) => {
        document.getElementById("body").classList.replace('show', 'hide');
        setTimeout(() => {

            document.getElementById("body").innerHTML = content;
            document.getElementById("body").classList.replace('hide', 'show');
            setTimer()
            move(10)
        }, 500);
    })
    .catch((error) => { console.log(error); });
}
function setTimer() {
    clearTimeout(timeoutID);
    timeoutID = setTimeout(logout, 10500);
}


// logout automatically
function move(sec) {
    let i = 0;
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
move(10)   // start progress bar with 10 sec
function logout () {
    location.href = '/logout';
}



