from keycloak import KeycloakAdmin, KeycloakOpenID, ConnectionManager
from keycloak.exceptions import KeycloakGetError


class PatchedKeycloakAdmin(KeycloakAdmin):
    def refresh_token(self):
        try:
            super().refresh_token()
        except KeycloakGetError as e:
            if e.response_code == 400 and b'No refresh token' in e.response_body:
                self.get_token()
                self.connection.add_param_headers('Authorization', 'Bearer ' + self.token.get('access_token'))
            else:
                raise

    def get_token(self):
        # The original library wanted to always use the master realm here in case a client_secret_key is set which
        # would not work for clients wanting to perform some action outside the master realm.
        # Should be fixed by https://github.com/marcospereirampj/python-keycloak/pull/226 at some point
        token_realm_name = self.realm_name if self.client_secret_key else self.user_realm_name or self.realm_name
        self.keycloak_openid = KeycloakOpenID(server_url=self.server_url, client_id=self.client_id,
                                              realm_name=token_realm_name, verify=self.verify,
                                              client_secret_key=self.client_secret_key,
                                              custom_headers=self.custom_headers)

        grant_type = ["password"]
        if self.client_secret_key:
            grant_type = ["client_credentials"]
            if self.user_realm_name:
                self.realm_name = self.user_realm_name

        self._token = self.keycloak_openid.token(self.username, self.password, grant_type=grant_type)

        headers = {
            'Authorization': 'Bearer ' + self.token.get('access_token'),
            'Content-Type': 'application/json'
        }

        if self.custom_headers is not None:
            # merge custom headers to main headers
            headers.update(self.custom_headers)

        self._connection = ConnectionManager(base_url=self.server_url,
                                             headers=headers,
                                             timeout=60,
                                             verify=self.verify)
