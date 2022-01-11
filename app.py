
from flask import Flask, render_template, request
from flask_oidc import OpenIDConnect
from webauthn import generate_registration_options, generate_authentication_options, options_to_json, base64url_to_bytes
from webauthn.helpers.structs import\
    AuthenticationExtensionsLargeBlobInputs, \
    LargeBlobSupport, AuthenticatorSelectionCriteria, ResidentKeyRequirement, PublicKeyCredentialDescriptor

app = Flask(__name__)
app.config["OIDC_CLIENT_SECRETS"] = "client_secrets.json"
app.config["OIDC_SCOPES"] = ["openid", "profile", "email"]
app.config["SECRET_KEY"] = "adfsdfsdfsdfsdf"
oidc = OpenIDConnect(app)

credentialID = b"1234567890"


def largeBlobMessage():
    return b'abcdefghijklmnopqrstuvwxyz'


@app.route('/')
@oidc.require_login
def index():
    return render_template('index.html', username=oidc.user_getfield("preferred_username"))


@app.route('/register')
@oidc.require_login
def register():
    registration_options = generate_registration_options(
        rp_id="localhost",
        rp_name="Example Inc.",
        user_id="12345",
        user_name="alice@example.com",
        user_display_name='Alice Liddell',
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            support=LargeBlobSupport.REQUIRED
        ),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED
        )
    )

    return options_to_json(registration_options)



@app.route('/register-response', methods=['POST'])
def register_response():
    global credentialID
    credentialID = base64url_to_bytes(request.get_json(force=True)['test'])
    return ''


@app.route('/write-blob')
def writeBlob():
    authentication_options = generate_authentication_options(
        rp_id='localhost',
        allow_credentials=[PublicKeyCredentialDescriptor(id=credentialID)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            write=largeBlobMessage()
        )
    )

    return options_to_json(authentication_options)


@app.route('/read-blob')
def readBlob():
    authentication_options = generate_authentication_options(
        rp_id='localhost',
        allow_credentials=[PublicKeyCredentialDescriptor(id=credentialID)],
        large_blob_extension=AuthenticationExtensionsLargeBlobInputs(
            read=True
        )
    )

    return options_to_json(authentication_options)


@app.route('/challenge')
@oidc.require_login
def challenge():
    return {}


if __name__ == '__main__':
    app.run(ssl_context=("cert.pem", "key.pem"), debug=True)
