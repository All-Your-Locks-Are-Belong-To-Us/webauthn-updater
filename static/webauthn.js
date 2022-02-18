function registerWithSelectedAuthenticator() {
    console.log('REGISTERING CREDENTIAL')
    fetch('/register')
        .then(response => response.json())
        .then((registerParams) => {
            return createExtended({
                'publicKey': registerParams
            })
        })
        .then((newCredentialInfo) => {
            console.log('SUCCESS', newCredentialInfo);
            return fetch('/register-response', {
                method: 'POST',
                body: JSON.stringify(newCredentialInfo)
            })
        })
        .then(console.log)
        .catch(requestFailure)
}

function identifyCredential() {
    console.log('IDENTIFYING CREDENTIAL')
    fetch('/identify-credential')
        .then(response => response.json())
        .then((authenticateParams) => {
            console.log(authenticateParams);
            return getExtended({ 'publicKey': authenticateParams })
        })
        .then((getAssertionResponse) => {
            console.log('SUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse)
            return fetch('/authentication-response', {
                method: 'POST',
                body: JSON.stringify(getAssertionResponse)
            })
        })
        .then(response => response.text())
        .then(credential_id => {
            document.getElementById('identified_credential').innerText = credential_id;
        })
        .catch(requestFailure)
}

function writeLargeBlob() {
    console.log('WRITING LARGE BLOB')
    fetch('/write-blob')
        .then(response => response.json())
        .then((authenticateParams) => {
            console.log(authenticateParams);
            return getExtended({ 'publicKey': authenticateParams })
        })
        .then((getAssertionResponse) => {
            console.log('SUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse)
        })
        .catch(requestFailure)
}

function readLargeBlob() {
    console.log('READING LARGE BLOB')
    fetch('/read-blob')
        .then(response => response.json())
        .then((authenticateParams) => {
            console.log(authenticateParams);
            return getExtended({ 'publicKey': authenticateParams })
        })
        .then((getAssertionResponse) => {
            console.log('SUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse)
            document.getElementById('largeBlobData').innerText =
                hexStringEncode(base64Decode(getAssertionResponse.clientExtensionResults.largeBlob.blob));
        })
        .catch(requestFailure)
}

///// HELPERS

function base64Decode(base64String) {
    return Uint8Array.from(
        window.atob(base64String.replace(/_/g, '/').replace(/-/g, '+')),
        c=>c.charCodeAt(0)
    )
}

function hexStringEncode(byteArray) {
    return byteArray.reduce(function(memo, i) {return memo + ('0' + i.toString(16)).slice(-2)}, '');
}

function requestFailure(error) {
    alert('Operation failed, see browser console!')
    console.log('FAIL', error)
}