function checkForm() {
    var errorsFound = false;
    var checkTitle = document.forms['formCheck']['posttitle'].value;
    var checkText = document.forms['formCheck']['posttext'].value;

    if (checkTitle === "") {
        document.getElementById('titleError').classList.remove("hidden");
        errorsFound = true;
    }

    if (checkText === "") {
        document.getElementById('textError').classList.remove("hidden");
        errorsFound = true;
    }

    if (errorsFound) {
        return false;
    }

    return true;
}

/* event listener */
document.forms['formCheck']['posttitle'].addEventListener('input', resetTitleError);
document.forms['formCheck']['posttext'].addEventListener('input', resetTextError);


function resetTitleError() {
   document.getElementById('titleError').classList.add("hidden");
}

function resetTextError() {
   document.getElementById('textError').classList.add("hidden");
}