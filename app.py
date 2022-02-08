import json
import os
from base64 import b64encode
import re

from ecdsa import SigningKey
from flask import Flask, render_template, request, redirect, session
from flask_oidc import OpenIDConnect
from patched_keycloak_admin import PatchedKeycloakAdmin
from webauthn import (
    generate_registration_options, generate_authentication_options, options_to_json,
    verify_registration_response, verify_authentication_response, base64url_to_bytes, bytes_to_base64url
)
from webauthn.helpers.structs import (
    AuthenticationExtensionsLargeBlobInputs, LargeBlobSupport, AuthenticatorSelectionCriteria, ResidentKeyRequirement,
    PublicKeyCredentialDescriptor, RegistrationCredential, AuthenticationCredential, AttestationConveyancePreference,
    UserVerificationRequirement, CredentialProtectionPolicy
)

HOST_URL = os.environ["WAU_HOST_URL"]
RP_ID = re.search(r'https?://([^:]+)', HOST_URL).group(1)

app = Flask(__name__)
app.config["OIDC_CLIENT_SECRETS"] = "client_secrets.json"
app.config["OIDC_SCOPES"] = ["openid", "profile", "email"]
app.config["SECRET_KEY"] = "adfsdfsdfsdfsdf"
app.config["OVERWRITE_REDIRECT_URI"] = f"{HOST_URL}/oidc_callback"
oidc = OpenIDConnect(app)
signing_key = SigningKey.from_string(base64url_to_bytes(os.environ["WAU_SIGNING_KEY"])) if "WAU_SIGNING_KEY" in os.environ else None
keycloak_admin = PatchedKeycloakAdmin(server_url=f"https://{os.environ['WAU_KEYCLOAK_HOST_NAME']}/auth/",
                                      client_id=os.environ['WAU_KEYCLOAK_CLIENT_ID'],
                                      client_secret_key=os.environ['WAU_KEYCLOAK_CLIENT_SECRET'],
                                      realm_name="hotsir",
                                      verify=True,
                                      auto_refresh_token=['get', 'put', 'post', 'delete'])


def parse_credential_data(credential):
    credential["credentialData"] = json.loads(credential["credentialData"])
    return credential


def get_credentials_for_user(user_id):
    credentials = json.loads(keycloak_admin.raw_get(f"admin/realms/hotsir/users/{user_id}/credentials").content)
    return list(map(parse_credential_data, filter(lambda credential: credential['type'] == 'webauthn', credentials)))


def get_signed_access_rights():
    access_rights = oidc.user_getfield("access_rights")
    return json.dumps({
        "access_rights": access_rights,
        "credentialPublicKey": session["selected_credential_publicKey"],
        "signature": bytes_to_base64url(signing_key.sign(bytes(f"{access_rights}{session['selected_credential_publicKey']}", "utf-8"))) if signing_key is not None else ""
    }).encode("utf-8")


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
        rp_id=RP_ID,
        rp_name="Webauthn Updater.",
        user_id=oidc.user_getfield('sub'),
        user_name=oidc.user_getfield('preferred_username'),
        user_display_name=oidc.user_getfield('name'),
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            support=LargeBlobSupport.REQUIRED,
        ),
        credential_protection_policy=CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.DISCOURAGED
        ),
        attestation=AttestationConveyancePreference.DIRECT,
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
        expected_rp_id=RP_ID,
        expected_origin=HOST_URL
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
    stored_credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        # We cannot rely completely on the discoverable credential feature here, as that could make the authenticator
        # select a credential from another user.
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential["credentialData"]["credentialId"]))
            for credential in stored_credentials
        ]
    )
    session["last_challenge"] = authentication_options.challenge

    return options_to_json(authentication_options)


@app.route('/authentication-response', methods=['POST'])
@oidc.require_login
def authentication_response():
    stored_credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    if len(stored_credentials) == 0:
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
        expected_rp_id=RP_ID,
        expected_origin=HOST_URL,
        credential_public_key=base64url_to_bytes(stored_credential["credentialData"]["credentialPublicKey"]),
        credential_current_sign_count=0
    )
    session["selected_credential_id"] = verified_authentication.credential_id
    session["selected_credential_publicKey"] = stored_credential["credentialData"]["credentialPublicKey"]

    return b64encode(verified_authentication.credential_id)


@app.route('/write-blob')
@oidc.require_login
def write_blob():
    credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    if len(credentials) == 0:
        return 'User has not registered a credential', 400
    if (selected_credential_id := session["selected_credential_id"]) is None:
        return "User has not selected a credential to write to", 400

    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=selected_credential_id)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            write=get_signed_access_rights()
        )
    )

    return options_to_json(authentication_options)


@app.route('/read-blob')
@oidc.require_login
def read_blob():
    credentials = get_credentials_for_user(oidc.user_getfield('sub'))
    if len(credentials) == 0:
        return 'User has not registered a credential', 400
    if (selected_credential_id := session["selected_credential_id"]) is None:
        return "User has not selected a credential to write to", 400

    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=selected_credential_id)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            read=True
        )
    )

    return options_to_json(authentication_options)


if __name__ == '__main__':
    app.run(port=os.getenv("WAU_SERVER_PORT", 8002), host="localhost")
