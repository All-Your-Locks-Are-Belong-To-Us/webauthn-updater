# WebAuthn Updater

This project provides a demonstration of writing data to a FIDO authenticator using WebAuthn and the CTAP 2.1 largeBlob extension. The data is loaded from a Keycloak instance via OIDC.

## Setup

This project assumes Python 3.9. Make sure to have Pip and Pipenv installed.

As the py_webauthn python module has been extended to support the largeBlob extension, it needs to be installed locally. Navigate to the `py_webauthn` directory and run `python setup.py install` to do so.

The remaining dependencies can be installed using `pipenv install`.

For the app to work properly, some environment variables need to be set:

| Name | Local value | Deployment Value |
|---|---|---|
|WAU_HOST_NAME|`localhost`|`wau.felixgohla.de`|
|WAU_KEYCLOAK_HOST_NAME|`kc.felixgohla.de`|`kc.felixgohla.de`|
|WAU_KEYCLOAK_CLIENT_ID|`webauthn-updater`|`deployed-webauthn-updater`|
|WAU_KEYCLOAK_CLIENT_SECRET|*retrieve from Keycloak*|*retrieve from Keycloak*|

Generate the OIDC config file using the environment variables by running `envsubst < client_secrets.tmpl.json > client_secrets.json`

Start the app via `pipenv run python app.py`

## Acknowledgements

The [WebAuthn Javascript serialization helper](static/webauthn-json.browser-global.extended.js) is taken from the [@github/webauthn-json project](https://github.com/github/webauthn-json).
