import dataclasses
import random
from typing import List
from base64 import b64encode

from flask import Flask, render_template, request, redirect
from flask_oidc import OpenIDConnect
from webauthn import generate_registration_options, generate_authentication_options, options_to_json, \
    verify_registration_response, verify_authentication_response
from webauthn.helpers.structs import\
    AuthenticationExtensionsLargeBlobInputs, \
    LargeBlobSupport, AuthenticatorSelectionCriteria, ResidentKeyRequirement, PublicKeyCredentialDescriptor, \
    RegistrationCredential, AuthenticationCredential

app = Flask(__name__)
app.config["OIDC_CLIENT_SECRETS"] = "client_secrets.json"
app.config["OIDC_SCOPES"] = ["openid", "profile", "email"]
app.config["SECRET_KEY"] = "adfsdfsdfsdfsdf"
oidc = OpenIDConnect(app)
app.users = []

HOST_NAME = "wau.felixgohla.de"
HOST_URL = f"https://{HOST_NAME}"


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


def find_user_by_name(user_name):
    for user in app.users:
        if user.user_name == user_name:
            return user
    return None


def find_or_create_user(user_name):
    user = find_user_by_name(user_name)
    if user is not None:
        return user
    user = User(
        str(random.randint(10000, 99999)),
        user_name
    )
    app.users.append(user)
    return user


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
    user = find_or_create_user(oidc.user_getfield('preferred_username'))

    registration_options = generate_registration_options(
        rp_id=HOST_NAME,
        rp_name="Webauthn Updater.",
        user_id=user.user_id,
        user_name=user.user_name,
        user_display_name=user.user_name,
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            support=LargeBlobSupport.REQUIRED
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED
        )
    )
    user.last_challenge = registration_options.challenge

    return options_to_json(registration_options)


@app.route('/register-response', methods=['POST'])
@oidc.require_login
def register_response():
    credential = RegistrationCredential.parse_raw(request.get_data())
    user = find_or_create_user(oidc.user_getfield('preferred_username'))
    verified_registration = verify_registration_response(
        credential=credential,
        expected_challenge=user.last_challenge,
        expected_rp_id=HOST_NAME,
        expected_origin=HOST_URL
    )

    user.find_or_create_credential(
        verified_registration.credential_id,
        verified_registration.credential_public_key
    )

    return '', 204


@app.route('/identify-credential')
@oidc.require_login
def identify_credential():
    user: User = find_user_by_name(oidc.user_getfield('preferred_username'))
    if user is None:
        return 'User has not registered a credential', 400

    authentication_options = generate_authentication_options(
        rp_id=HOST_NAME
    )
    user.last_challenge = authentication_options.challenge

    return options_to_json(authentication_options)


@app.route('/authentication-response', methods=['POST'])
@oidc.require_login
def authentication_response():
    user: User = find_user_by_name(oidc.user_getfield('preferred_username'))
    if user is None:
        return 'User has not registered a credential', 400
    credential = AuthenticationCredential.parse_raw(request.get_data())
    stored_credential = user.find_credential_by_id(credential.raw_id)
    if stored_credential is None:
        return 'Credential with this ID is not registered', 400
    verified_authentication = verify_authentication_response(
        credential=credential,
        expected_challenge=user.last_challenge,
        expected_rp_id=HOST_NAME,
        expected_origin=HOST_URL,
        credential_public_key=stored_credential.public_key,
        credential_current_sign_count=0
    )
    user.selected_credential = stored_credential

    return b64encode(verified_authentication.credential_id)


@app.route('/write-blob')
@oidc.require_login
def write_blob():
    user: User = find_user_by_name(oidc.user_getfield('preferred_username'))
    if user is None:
        return 'User has not registered a credential', 400
    if user.selected_credential is None:
        return 'No credential for user is selected', 400

    authentication_options = generate_authentication_options(
        rp_id=HOST_NAME,
        allow_credentials=[PublicKeyCredentialDescriptor(id=user.selected_credential.id)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            write=f'{b64encode(user.selected_credential.id).decode("UTF-8")} can open {str(random.randint(0, 100))}% of our doors :)'.encode('UTF-8')
        )
    )

    return options_to_json(authentication_options)


@app.route('/read-blob')
@oidc.require_login
def read_blob():
    user: User = find_user_by_name(oidc.user_getfield('preferred_username'))
    if user is None:
        return 'User has not registered a credential', 400
    if user.selected_credential is None:
        return 'No credential for user is selected', 400

    authentication_options = generate_authentication_options(
        rp_id=HOST_NAME,
        allow_credentials=[PublicKeyCredentialDescriptor(id=user.selected_credential.id)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            read=True
        )
    )

    return options_to_json(authentication_options)


if __name__ == '__main__':
    app.run(port=8002)
