"""Token utilities."""
import json

import requests
import six
from django.core.exceptions import SuspiciousOperation, ImproperlyConfigured
from django.utils.encoding import smart_bytes, smart_text, force_bytes
from django.utils.functional import cached_property
from josepy import JWK, JWS, b64decode, Header

from mozilla_django_oidc.utils import import_from_settings


class JwsToken:

    def __init__(self, token):
        """Initialize."""
        self._token = force_bytes(token)

        self.OIDC_RP_CLIENT_SECRET = self.get_settings('OIDC_RP_CLIENT_SECRET')
        self.OIDC_OP_JWKS_ENDPOINT = self.get_settings(
            'OIDC_OP_JWKS_ENDPOINT', None,
        )
        self.OIDC_RP_SIGN_ALGO = self.get_settings(
            'OIDC_RP_SIGN_ALGO', 'HS256',
        )
        self.OIDC_RP_IDP_SIGN_KEY = self.get_settings(
            'OIDC_RP_IDP_SIGN_KEY', None,
        )

        if (
            self.OIDC_RP_SIGN_ALGO.startswith('RS') and
            (
                self.OIDC_RP_IDP_SIGN_KEY is None and
                self.OIDC_OP_JWKS_ENDPOINT is None
            )
        ):
            raise ImproperlyConfigured(
                '{} alg requires OIDC_RP_IDP_SIGN_KEY '
                'or OIDC_OP_JWKS_ENDPOINT to be configured.' %
                self.OIDC_RP_SIGN_ALGO,
            )

    @cached_property
    def payload(self):
        """Get payload."""
        key = self._get_key(self._token)
        return self._get_payload_data(self._token, key)

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    def _retrieve_matching_jwk(self, token):
        """Get the signing key by exploring the JWKS endpoint of the OP."""
        response_jwks = requests.get(
            self.OIDC_OP_JWKS_ENDPOINT,
            verify=self.get_settings('OIDC_VERIFY_SSL', True)
        )
        response_jwks.raise_for_status()
        jwks = response_jwks.json()

        # Compute the current header from the given token to find a match
        jws = JWS.from_compact(token)
        json_header = jws.signature.protected
        header = Header.json_loads(json_header)

        key = None
        for jwk in jwks['keys']:
            if jwk['kid'] != smart_text(header.kid):
                continue
            if 'alg' in jwk and jwk['alg'] != smart_text(header.alg):
                raise SuspiciousOperation('alg values do not match.')
            key = jwk
        if key is None:
            raise SuspiciousOperation('Could not find a valid JWKS.')
        return key

    def _get_key(self, token):
        if self.OIDC_RP_SIGN_ALGO.startswith('RS'):
            if self.OIDC_RP_IDP_SIGN_KEY is not None:
                key = self.OIDC_RP_IDP_SIGN_KEY
            else:
                key = self._retrieve_matching_jwk(token)
        else:
            key = self.OIDC_RP_CLIENT_SECRET
        return key

    def _get_payload_data(self, token, key):
        """Helper method to get the payload of the JWT token."""
        if self.get_settings('OIDC_ALLOW_UNSECURED_JWT', False):
            header, payload_data, signature = token.split(b'.')
            header = json.loads(smart_text(b64decode(header)))

            # If config allows unsecured JWTs check the header
            # and return the decoded payload
            if 'alg' in header and header['alg'] == 'none':
                return b64decode(payload_data)

        # By default fallback to verify JWT signatures
        data = self._verify_jws(token, key)
        return json.loads(data)

    def _verify_jws(self, payload, key):
        """
        Verify the given JWS payload with the given key and return the payload.
        """
        jws = JWS.from_compact(payload)

        try:
            alg = jws.signature.combined.alg.name
        except KeyError:
            msg = 'No alg value found in header'
            raise SuspiciousOperation(msg)

        if alg != self.OIDC_RP_SIGN_ALGO:
            msg = "The provider algorithm {!r} does not match the client's " \
                  "OIDC_RP_SIGN_ALGO.".format(alg)
            raise SuspiciousOperation(msg)

        if isinstance(key, six.string_types):
            # Use smart_bytes here since the key string comes from settings.
            jwk = JWK.load(smart_bytes(key))
        else:
            # The key is a json returned from the IDP JWKS endpoint.
            jwk = JWK.from_json(key)

        if not jws.verify(jwk):
            msg = 'JWS token verification failed.'
            raise SuspiciousOperation(msg)

        return jws.payload
