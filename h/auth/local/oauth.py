from datetime import datetime
import os

import jwt
from oauthlib.oauth2 import (
    ClientCredentialsGrant,
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
)
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.exceptions import BadCSRFToken
from pyramid.interfaces import ISessionFactory
from pyramid.session import check_csrf_token, SignedCookieSessionFactory

from h.api import get_consumer

EPOCH = datetime(1970, 1, 1)
JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


def posix_seconds(t):
    return int((t - EPOCH).total_seconds())


class JWTBearerGrant(ClientCredentialsGrant):
    def validate_token_request(self, request):
        params = request.params
        for param in ('grant_type', 'assertion'):
            if param not in params:
                raise InvalidRequestError(
                    'Request is missing {} parameter.'.format(param),
                    request=request)

        for param in ('grant_type', 'assertion', 'scope'):
            if param in request.duplicate_params:
                raise InvalidRequestError(
                    'Duplicate {} parameter.'.format(param),
                    request=request)

        assertion = str(params['assertion'])

        try:
            appstruct = jwt.decode(assertion, verify=False)
        except jwt.DecodeError:
            raise InvalidGrantError('Invalid assertion format.',
                                    request=request)

        for claim in ('iss', 'sub', 'aud', 'exp'):
            if claim not in appstruct:
                raise InvalidGrantError(
                    'Assertion is missing {} claim.'.format(claim),
                    request=request)

        if appstruct['aud'] != request.path_url:
            raise InvalidGrantError(
                'Assertion audience must be {}.'.format(request.path_url),
                request=request)

        if appstruct['exp'] <= posix_seconds(datetime.utcnow()):
            raise InvalidGrantError('Assertion has expired.', request=request)

        request.client_id = appstruct['iss']
        request.client = get_consumer(request)

        # XXX: Fix minor formatting errors -- remove after dropping UUID
        request.client_id = request.client.client_id

        if request.client is None:
            raise InvalidClientError(
                'Unrecognized issuer {}.'.format(request.client_id),
                request=request)

        try:
            verified = jwt.decode(assertion, request.client.client_secret)
        except jwt.DecodeError:
            raise InvalidGrantError(
                'Invalid assertion signature.', request=request)

        userid = '{}@{}.accounts.{}'.format(
            verified['sub'],
            request.client_id,
            request.domain
        )
        add_credentials(request, userId=userid)


def add_credentials(request, **credentials):
    new_credentials = (request.extra_credentials or {})
    new_credentials.update(credentials)
    request.extra_credentials = new_credentials


class SessionAuthenticationGrant(ClientCredentialsGrant):
    def validate_token_request(self, request):
        try:
            check_csrf_token(request, token='assertion')
        except BadCSRFToken:
            raise InvalidClientError(request=request)

        request.client = get_consumer(request)

        if request.client is None:
            raise InvalidClientError(request=request)

        request.client_id = request.client_id or request.client.client_id

        userid = request.authenticated_userid
        if userid:
            add_credentials(request, userId=userid)


def session_from_config(settings, prefix='session.'):
    """Return a session factory from the provided settings."""
    secret_key = '{}secret'.format(prefix)
    secret = settings.get(secret_key)
    if secret is None:
        # Get 32 bytes (256 bits) from a secure source (urandom) as a secret.
        # Pyramid will add a salt to this. The salt and the secret together
        # will still be less than the, and therefore right zero-padded to,
        # 1024-bit block size of the default hash algorithm, sha512. However,
        # 256 bits of random should be more than enough for session secrets.
        secret = os.urandom(32)

    return SignedCookieSessionFactory(secret)


def includeme(config):
    config.include('pyramid_oauthlib')
    config.add_grant_type(JWTBearerGrant, JWT_BEARER)
    config.add_grant_type(SessionAuthenticationGrant)

    # Configure the authentication policy
    authn_debug = config.registry.settings.get('debug_authorization')
    authn_policy = SessionAuthenticationPolicy(prefix='', debug=authn_debug)
    config.set_authentication_policy(authn_policy)

    def register():
        if config.registry.queryUtility(ISessionFactory) is None:
            session_factory = session_from_config(config.registry.settings)
            config.registry.registerUtility(session_factory, ISessionFactory)

    config.action(None, register, order=1)
