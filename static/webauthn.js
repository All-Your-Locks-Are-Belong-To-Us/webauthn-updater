function registerCredential() {
    getMakeCredentialChallenge()
        .then((credentialChallenge) => {
          navigator.credentials.create({ 'publicKey': credentialChallenge })
        })
        .then((newCredentialInfo) => {
            console.log('SUCCESS', newCredentialInfo)
        })
        .catch((error) => {
            console.log('FAIL', error)
        })
}

function getMakeCredentialChallenge() {
    let challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    let userID = 'Kosv9fPtkDoh4Oz7Yq/pVgWHS8HhdlCto5cR0aBoVMw='
    let id = Uint8Array.from(window.atob(userID), c=>c.charCodeAt(0))

    return Promise.resolve({
        'challenge': challenge,

        'rp': {
            'name': 'Example Inc.'
        },

        'user': {
            'id': id,
            'name': 'alice@example.com',
            'displayName': 'Alice Liddell'
        },

        'pubKeyCredParams': [
            { 'type': 'public-key', 'alg': -7  },
            { 'type': 'public-key', 'alg': -257 }
        ]
    });
}

function authenticateCredential() {
    let publicKey = {
        challenge: challenge,

        allowCredentials: [
            { type: "public-key", id: credentialId }
        ]
    }

    navigator.credentials.get({ 'publicKey': publicKey })
      .then((getAssertionResponse) => {
          alert('SUCCESSFULLY GOT AN ASSERTION! Open your browser console!')
          console.log('SUCCESSFULLY GOT AN ASSERTION!', getAssertionResponse)
      })
      .catch((error) => {
          alert('Open your browser console!')
          console.log('FAIL', error)
      })
}

function readLargeBlob() {

}