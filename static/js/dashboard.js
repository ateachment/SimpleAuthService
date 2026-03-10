// dashboard.js

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

    // WebAuthn benötigt Binary
    options.challenge = base64urlToUint8Array(options.challenge);
    options.user.id = base64urlToUint8Array(options.user.id);

    const credential = await navigator.credentials.create({
        publicKey: options
    });

    const data = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
            attestationObject: bufferToBase64url(credential.response.attestationObject)
        }
    };

    const finish = await fetch("/passkey/register/finish", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const result = await finish.json();
    console.log(result);
}
// helper functions to convert between base64url and ArrayBuffer (required for passkey registration)
function base64urlToUint8Array(base64url) {

    const padding = "=".repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding)
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const raw = atob(base64);
    const buffer = new Uint8Array(raw.length);

    for (let i = 0; i < raw.length; ++i) {
        buffer[i] = raw.charCodeAt(i);
    }

    return buffer;
}
// helper function to convert ArrayBuffer to base64url (required for passkey registration)
function bufferToBase64url(buffer) {

    const bytes = new Uint8Array(buffer);
    let str = "";

    for (const b of bytes) {
        str += String.fromCharCode(b);
    }

    return btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
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



