import json
import os
from datetime import datetime
from urllib.parse import urlencode, unquote

import httpx
from jose import jwt
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.model import Account
from src.auth.service import get_password_hash
from src.user.model import User


async def make_request(method, url, params=None, data=None, headers=None):
    async with httpx.AsyncClient() as client:
        if method == 'GET':
            response = await client.get(url, params=params)
        elif method == 'POST':
            response = await client.post(url, data=data, headers=headers)
        # Другие методы HTTP: PUT, DELETE и т.д.
        else:
            raise ValueError(f"Неподдерживаемый метод HTTP: {method}")

        response.raise_for_status()
        return response.json()


class AsyncBaseUserOAuth:
    """
    Base class for user registration via social networks
    """

    def __init__(self, code: str, session: AsyncSession):
        self.code = code  # Cross-site request forgery
        self.session = session
        self.client_id = None
        self.client_secret = None
        self.redirect_uri = None
        self.ctrate_user = False
        self.access_token = None
        self.email = None
        self.name = None
        self.surname = None
        self.city = None
        self.valid = False
        self.error_massage = None
        self.uid = None
        self.user = None
        self.account = None

    def clean_data(self):
        data = {
            'email': self.email,
            'first_name': self.surname,
            'confirmationed_email': True
        }
        valid_data = {key: value for key, value in data.items() if value}
        return valid_data

    async def account_exists(self):
        async with self.session.begin():
            stmt = select(Account).where(
                or_(
                    Account.email == self.email,
                    and_(
                        Account.open_id == self.uid,
                        Account.type == self.provider
                    )
                )
            )
            result = await self.session.execute(stmt)
            user = result.scalar_one_or_none()
            return user is not None

    async def get_or_create_user(self):
        """Create user in the database"""
        account_exists = await self.account_exists()
        if not account_exists:
            async with self.session.begin():
                user = User(name=self.name, surname=self.surname)
                self.session.add(user)  # Save the user in the session
                await self.session.flush()  # Generate the user ID

                account = Account(
                    email=self.email, open_id=self.uid, type=self.provider,
                    password=get_password_hash('password'), user_id=user.id
                )
                self.ctrate_user = True
                self.account = account
                self.session.add(account)  # Save the account in the session
                await self.session.flush()  # Generate the account ID
        else:
            query = select(Account).where(
                or_(
                    Account.email == self.email,
                    and_(
                        Account.open_id == self.uid,
                        Account.type == self.provider
                    )
                )
            )
            result = await self.session.execute(query)
            account = result.scalar_one_or_none()  # Fetch a single result or None

        self.account = account
        self.valid = True


def update_profile(self):
    pass


class AsyncFBUserOAuth(AsyncBaseUserOAuth):
    """
    Class for authorization in Facebook
    """
    provider = 'Facebook'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_id = os.environ.get("SOCIAL_AUTH_FACEBOOK_KEY")
        self.client_secret = os.environ.get("SOCIAL_AUTH_FACEBOOK_SECRET")
        self.redirect_uri = os.environ.get("SOCIAL_AUTH_FACEBOOK_REDIRECT_URL")

    async def get_account(self):
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'code': self.code}
        uri = f'https://graph.facebook.com/v17.0/oauth/access_token'
        result = await make_request("GET", uri, params=params)
        self.access_token = result.get('access_token')
        await self.get_user_id()

    async def get_user_id(self):
        params = {'access_token': self.access_token}
        uri = 'https://graph.facebook.com/me'
        result = await make_request("GET", uri, params=params)
        self.uid = result.get('id')
        self.name = result.get('name')
        await self.provider_profile()

    async def provider_profile(self):
        """
        method gets user information from facebook
        """
        params = {
            'fields': 'id,email,birthday,first_name,gender,last_name,middle_name,picture,hometown',
            'access_token': self.access_token}
        uri = f'https://graph.facebook.com/{self.uid}'
        response = await make_request("GET", uri, params=params)
        data = response

        if data is None:
            return

        self.email = data.get('email')
        self.name = data.get('first_name')
        self.surname = data.get('last_name')
        await self.get_or_create_user()


class AsyncGoogleUserOAuth(AsyncBaseUserOAuth):
    """
    Class for authorization in Google
    """
    provider = 'Google'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
        self.client_secret = os.environ.get("SOCIAL_AUTH_GOOGLE_SECRET")
        self.redirect_uri = os.environ.get("SOCIAL_AUTH_GOOGLE_REDIRECT_URL")

    async def get_account(self):
        url = "https://www.googleapis.com/oauth2/v4/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': self.code}
        result = await make_request("POST", url, headers=headers, data=urlencode(payload))

        self.access_token = result.get('access_token')
        await self.get_user_id()

    async def get_user_id(self):
        params = {'access_token': self.access_token, 'alt': 'json'}
        uri = 'https://www.googleapis.com/oauth2/v1/userinfo'
        data = await make_request("GET", uri, params=params)

        if data is None:
            return

        self.uid = data.get('id')
        self.name = data.get('name')
        self.surname = data.get('family_name')
        self.email = data.get('email')
        await self.get_or_create_user()


class AsyncAppleUserOAuth(AsyncBaseUserOAuth):
    """
    Class for authorization in Apple
    """
    provider = 'Apple'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_id = os.environ.get("SOCIAL_AUTH_APPLE_KEY")
        self.team_id = os.environ.get("SOCIAL_AUTH_APPLE_TEAM_ID")
        self.client_secret = os.environ.get("SOCIAL_AUTH_APPLE_SECRET")
        self.redirect_uri = os.environ.get("SOCIAL_AUTH_APPLE_REDIRECT_URL")

    async def _create_jwt(self):
        claims = {
            'iss': self.team_id,
            'aud': 'https://appleid.apple.com',
            'sub': self.client_id,
            'iat': datetime.now().timestamp(),
            'exp': datetime.now().timestamp() + 5 * 60,
        }
        headers = {'kid': 'APPLEID_KEY_ID', 'alg': 'ES256'}

        client_secret = jwt.encode(payload=claims, key=self.client_secret, algorithm='ES256', headers=headers).decode(
            'utf-8')

    @staticmethod
    def get_apple_public_key():
        return make_request("GET", "https://appleid.apple.com/auth/keys")

    async def get_authorization_code_apple(self, data):
        uri = "https://appleid.apple.com/auth/token"

        payload = {
            'client_id': self.client_id,
            'client_secret': self._create_jwt,
            'grant_type': 'authorization_code',
            'code': data['code']}
        return await make_request("POST", uri, data=urlencode(payload))

    async def get_account(self, data):
        self.access_token = self.get_authorization_code_apple(data)
        if self.access_token['access_token']:
            spublic_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(self.get_apple_public_key))
            data = jwt.decode(self.access_token['id_token'],
                              self.public_key,
                              algorithm="RS256",
                              verify=True,
                              audience=self.client_id,
                              )

            self.uid = data['sub']
            self.name = data['email']
            self.surname = data['name']
            await self.get_or_create_user()
        return ""


def fb_authorize_client_url():
    endpoint = 'https://www.facebook.com/v17.0/dialog/oauth?'
    params = {
        'client_id': os.environ.get("SOCIAL_AUTH_FACEBOOK_KEY"),
        'redirect_uri': os.environ.get("SOCIAL_AUTH_FACEBOOK_REDIRECT_URL"),
        'state': "{st=statsssse123addsasdxczxczbc,ds=123456789}",
    }
    return endpoint + unquote(urlencode(params))


def google_authorize_client_url():
    endpoint = 'https://accounts.google.com/o/oauth2/v2/auth?'
    params = {
        'client_id': os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID"),
        'redirect_uri': os.environ.get("SOCIAL_AUTH_GOOGLE_REDIRECT_URL"),
        'scope': 'openid%20profile%20email',
        'response_type': 'code',
        'access_type': 'offline',
        'include_granted_scopes': 'true',
        'state': 'state_parameter_passthrough_value'}
    return endpoint + unquote(urlencode(params))


def apple_authorize_client_url():
    endpoint = 'https://appleid.apple.com/auth/authorize?'
    params = {
        'client_id': os.environ.get("SOCIAL_AUTH_APPLE_CLIENT_ID"),
        'redirect_uri': os.environ.get("SOCIAL_AUTH_APPLE_REDIRECT_URL"),
        'scope': 'email+name',
        'response_mode': 'form_post',
        'include_granted_scopes': 'true',
        'state': 'state_parameter_passthrough_value'}
    return endpoint + unquote(urlencode(params))
