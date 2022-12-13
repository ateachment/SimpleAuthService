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


