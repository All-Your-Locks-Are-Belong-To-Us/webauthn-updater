let credentialId = null;

function registerCredential() {
    fetch('/register')
        .then(response => response.json())
        .then((registerParams) => {
            console.log(registerParams);
            return navigator.credentials.create({
                'publicKey': prepareMessageParams(registerParams)
            })
        })
        .then((newCredentialInfo) => {
            console.log('SUCCESS', newCredentialInfo);
            credentialId = newCredentialInfo.rawId;
            return fetch('/register-response', {
                method: 'POST',
                body: JSON.stringify({
                    test: newCredentialInfo.id
                })
            })
        })
        .then(response =>console.log(response))
        .catch((error) => {
            console.log('FAIL', error)
        })
}

function prepareMessageParams(messageParams) {
    messageParams.challenge = base64Decode(messageParams.challenge);
    if (messageParams.user !== undefined) {
        messageParams.user.id = base64Decode(messageParams.user.id);
    }
    if (messageParams.allowCredentials !== undefined) {
        for (let i = 0; i < messageParams.allowCredentials.length; i++) {
            messageParams.allowCredentials[i].id = base64Decode(messageParams.allowCredentials[i].id);
        }
    }
    if (messageParams.extensions.largeBlob.write !== undefined) {
        messageParams.extensions.largeBlob.write = base64Decode(messageParams.extensions.largeBlob.write);
    }
    return messageParams;
}

function base64Decode(base64String) {
    return Uint8Array.from(
        window.atob(base64String.replace(/_/g, '/').replace(/-/g, '+')),
        c=>c.charCodeAt(0)
    )
}

function authenticateCredential() {
    fetch('/write-blob')
        .then(response => response.json())
        .then((authenticateParams) => {
            console.log(authenticateParams);
            return navigator.credentials.get({ 'publicKey': prepareMessageParams(authenticateParams) })
        })
        .then((getAssertionResponse) => {
          console.log('SUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse)
        })
        .catch((error) => {
          alert('Open your browser console!')
          console.log('FAIL', error)
        })
}

function readLargeBlob() {
    fetch('/read-blob')
        .then(response => response.json())
        .then((authenticateParams) => {
            console.log(authenticateParams);
            return navigator.credentials.get({ 'publicKey': prepareMessageParams(authenticateParams) })
        })
        .then((getAssertionResponse) => {
            console.log('SUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse)
            console.log(
                new TextDecoder().decode(getAssertionResponse.getClientExtensionResults().largeBlob.blob)
            )
        })
        .catch((error) => {
          alert('Open your browser console!')
          console.log('FAIL', error)
        })
}