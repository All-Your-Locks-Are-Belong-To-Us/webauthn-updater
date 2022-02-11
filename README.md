# WebAuthn Updater

This project provides a demonstration of writing data to a FIDO authenticator using WebAuthn and the CTAP 2.1 largeBlob extension. The data is loaded from a Keycloak instance via OIDC.

## Setup

This project assumes Python 3.9. Make sure to have Pip and Pipenv installed.

The dependencies of the app can be installed using `pipenv install`. (Note: the `webauthn` packages needed to be extended to support the largeBlob and credProtect extension. Therefore, the package is installed automatically from the local `py_webauthn` directory).

For the app to work properly, some environment variables need to be set:

| Name | Default value | Local value | Deployment Value |
|---|---|---|---|
|WAU_HOST_URL|*unset*|`http://localhost:5000`|`https://wau.felixgohla.de`|
|WAU_SERVER_PORT|8002|5000|*not required*|
|WAU_KEYCLOAK_HOST_NAME|*unset*|`kc.felixgohla.de`|`kc.felixgohla.de`|
|WAU_KEYCLOAK_CLIENT_ID|*unset*|`webauthn-updater`|`deployed-webauthn-updater`|
|WAU_KEYCLOAK_CLIENT_SECRET|*unset*|*retrieve from Keycloak*|*retrieve from Keycloak*|
|WAU_SIGNING_KEY_PATH|*unset*|*not required*|path to PEM file of the ECDSA signing key|

Generate the OIDC config file using the environment variables by running `envsubst < client_secrets.tmpl.json > client_secrets.json`

Generate the signing key by running `openssl ecparam -name prime192v1 -genkey -out sk.pem`

### Running in current shell session

Start the app via `pipenv run python app.py`

### Running as a system service

Alternatively, if you want to run the app as a system service, first copy `webauthn-updater.service` to the `/etc/systemd/system` directory.

Enable the service by running `systemctl enable webauthn-updater.service`.

As the app requires an environment variable to be set, run `systemctl edit webauthn-updater.service` and enter the following to the resulting text input prompt:

```shell
[Service]
Environment="WAU_HOST_URL=<your url value here>"
Environment="WAU_KEYCLOAK_CLIENT_ID=<your client id here>"
Environment="WAU_KEYCLOAK_CLIENT_SECRET=<your secret here>"
```

Finally, start the service with `systemctl start webauthn-updater.service`.

## Acknowledgements

The [WebAuthn Javascript serialization helper](static/webauthn-json.browser-global.extended.js) is taken from the [@github/webauthn-json project](https://github.com/All-Your-Locks-Are-Belong-To-Us/webauthn-json/tree/feature/credential-protection-policy).
