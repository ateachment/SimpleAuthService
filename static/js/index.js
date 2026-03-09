var token = "-1";

function login () {
    // post form data
    // var formData = new FormData(document.getElementById("myForm"));   // lazy but short
    // data = JSON.stringify(Object.fromEntries(formData.entries()))
    var formData = new FormData();
    formData.append("username", document.getElementById("username").value);
    formData.append("password", document.getElementById("password").value);
    data = JSON.stringify(Object.fromEntries(formData.entries()))
    // fetch post
    fetch("http://localhost:5000/auth/user/login", {
        method: "POST",
        headers: {
            'Content-Type': 'application/json'
        },
        body: data
    })

    // return server response as text
    .then((result) => {
        if (result.status != 200 && result.status != 403) //if not logged and if not wrong username/pwd
            throw Error(result.statusText);
        else
            return result.text();
    })
    // output response
    .then((response) => {
        console.log(response);
        const obj = JSON.parse(response);   // JavaScript JSON parse don’t support single quote.
        document.getElementById("response").innerHTML = "Token = " + obj.token
        token = obj.token
    })
    // error handling
    .catch((error) => { 
        console.log(error); 
        alert("Oops! Something went wrong!")
    });
}


// helper function to convert base64url string to ArrayBuffer (required for passkey login)
function base64urlToBuffer(base64url) {
    const padding = "=".repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding)
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const raw = window.atob(base64);
    const buffer = new Uint8Array(raw.length);

    for (let i = 0; i < raw.length; i++) {
        buffer[i] = raw.charCodeAt(i);
    }

    return buffer;
}



// function to handle passkey login flow
async function passkeyLogin() {

    // Server nach Login-Optionen für Passkey fragen
    const response = await fetch("/passkey/login/begin", {
        method: "POST"
    });

    // Challenge und Optionen vom Server erhalten
    const options = await response.json();

    // Challenge von Base64 → ArrayBuffer
    options.challenge = base64urlToBuffer(options.challenge);

    // Passkey vom Authenticator anfordern
    const credential = await navigator.credentials.get({
        publicKey: options
    });

    // Antwort des Authenticators an den Server senden
    await fetch("/passkey/login/finish", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(credential)
    });

    // Bei erfolgreicher Verifikation Weiterleitung
    window.location = "/dashboard";
}
