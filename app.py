import dataclasses
import json
import os
import random
from typing import List
from base64 import b64encode

from flask import Flask, render_template, request, redirect, session
from flask_oidc import OpenIDConnect
from keycloak import KeycloakAdmin
from webauthn import generate_registration_options, generate_authentication_options, options_to_json, \
    verify_registration_response, verify_authentication_response
from webauthn.helpers.structs import\
    AuthenticationExtensionsLargeBlobInputs, \
    LargeBlobSupport, AuthenticatorSelectionCriteria, ResidentKeyRequirement, PublicKeyCredentialDescriptor, \
    RegistrationCredential, AuthenticationCredential

from py_webauthn.webauthn import base64url_to_bytes
from py_webauthn.webauthn.helpers import bytes_to_base64url

app = Flask(__name__)
app.config["OIDC_CLIENT_SECRETS"] = "client_secrets.json"
app.config["OIDC_SCOPES"] = ["openid", "profile", "email"]
app.config["SECRET_KEY"] = "adfsdfsdfsdfsdf"
oidc = OpenIDConnect(app)
keycloak_admin = KeycloakAdmin(server_url=f"https://{os.environ['WAU_KEYCLOAK_HOST_NAME']}/auth/admin",
                               username=os.environ['WAU_KEYCLOAK_USERNAME'],
                               password=os.environ['WAU_KEYCLOAK_PASSWORD'],
                               realm_name="hotsir",
                               verify=True)


def parse_credential_data(credential):
    credential["credentialData"] = json.loads(credential["credentialData"])
    return credential


def get_credentials_for_user(user_id):
    credentials = json.loads(keycloak_admin.raw_get(f"admin/realms/hotsir/users/{user_id}/credentials").content)
    return map(parse_credential_data, filter(lambda credential: credential['type'] == 'webauthn', credentials))


@dataclasses.dataclass
class Credential:
    id: bytes = b''
    public_key: bytes = b''


@dataclasses.dataclass
class User:
    user_id: str
    user_name: str
    selected_credential: Credential = None
    last_challenge: bytes = b''
    credentials: List[Credential] = dataclasses.field(default_factory=list)

    def find_credential_by_id(self, credential_id):
        for credential in self.credentials:
            if credential.id == credential_id:
                return credential
        return None

    def find_or_create_credential(self, credential_id, credential_public_key):
        credential = self.find_credential_by_id(credential_id)
        if credential is not None:
            return credential
        credential = Credential(
            credential_id,
            credential_public_key
        )
        self.credentials.append(credential)
        return credential





@app.route('/')
@oidc.require_login
def index():
    return render_template('index.html', username=oidc.user_getfield("preferred_username"))


@app.route('/logout')
def logout():
    oidc.logout()
    return redirect('/')


@app.route('/register')
@oidc.require_login
def register():
    registration_options = generate_registration_options(
        rp_id="localhost",
        rp_name="Webauthn Updater.",
        user_id=oidc.user_getfield('sub'),
        user_name=oidc.user_getfield('preferred_username'),
        user_display_name=oidc.user_getfield('name'),
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            support=LargeBlobSupport.REQUIRED,
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED
        )
    )
    session["last_challenge"] = registration_options.challenge

    return options_to_json(registration_options)


@app.route('/register-response', methods=['POST'])
@oidc.require_login
def register_response():
    credential = RegistrationCredential.parse_raw(request.get_data())
    verified_registration = verify_registration_response(
        credential=credential,
        expected_challenge=session["last_challenge"],
        expected_rp_id='localhost',
        expected_origin='http://localhost:5000'
    )

    user_id = oidc.user_getfield('sub')
    credential = dict(
        type="webauthn",
        secretData="{}",
        userLabel="webauthn-updater",
        credentialData=json.dumps(dict(
            credentialId=bytes_to_base64url(verified_registration.credential_id),
            credentialPublicKey=bytes_to_base64url(verified_registration.credential_public_key),
            aaguid=verified_registration.aaguid,
            counter=verified_registration.sign_count,
            attestationStatementFormat=verified_registration.fmt,
            attestationStatement=bytes_to_base64url(verified_registration.attestation_object),
        ))
    )
    keycloak_admin.update_user(user_id=user_id, payload=dict(credentials=[credential]))

    return '', 204


@app.route('/identify-credential')
@oidc.require_login
def identify_credential():
    authentication_options = generate_authentication_options(
        rp_id='localhost',
    )
    session["last_challenge"] = authentication_options.challenge

    return options_to_json(authentication_options)


@app.route('/authentication-response', methods=['POST'])
@oidc.require_login
def authentication_response():
    stored_credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    if not stored_credentials:
        return 'User has not registered a credential', 400
    credential = AuthenticationCredential.parse_raw(request.get_data())
    stored_credential = None
    for cred in stored_credentials:
        if cred["credentialData"]["credentialId"] == credential.id:
            stored_credential = cred
    if stored_credential is None:
        return 'Credential with this ID is not registered', 400
    verified_authentication = verify_authentication_response(
        credential=credential,
        expected_challenge=session["last_challenge"],
        expected_rp_id='localhost',
        expected_origin='http://localhost:5000',
        credential_public_key=base64url_to_bytes(stored_credential["credentialData"]["credentialPublicKey"]),
        credential_current_sign_count=0
    )
    session["selected_credential"] = verified_authentication.credential_id

    return b64encode(verified_authentication.credential_id)


@app.route('/write-blob')
@oidc.require_login
def write_blob():
    credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    if not credentials:
        return 'User has not registered a credential', 400
    if not (selected_credential := session["selected_credential"]):
        return "User has not selected a credential to write to", 400

    authentication_options = generate_authentication_options(
        rp_id='localhost',
        allow_credentials=[PublicKeyCredentialDescriptor(id=selected_credential)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            write=f'{oidc.user_getfield("preferred_username")} can open {str(random.randint(0, 100))}% of our doors :)'.encode('UTF-8')
        )
    )

    return options_to_json(authentication_options)


@app.route('/read-blob')
@oidc.require_login
def read_blob():
    credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    if not credentials:
        return 'User has not registered a credential', 400
    if not (selected_credential := session["selected_credential"]):
        return "User has not selected a credential to write to", 400

    authentication_options = generate_authentication_options(
        rp_id='localhost',
        allow_credentials=[PublicKeyCredentialDescriptor(id=selected_credential)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            read=True
        )
    )

    return options_to_json(authentication_options)


if __name__ == '__main__':
    app.run(ssl_context=("cert.pem", "key.pem"), debug=True)
