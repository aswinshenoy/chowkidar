import graphene
from django.utils import timezone

from ..models import RefreshToken
from .decorators import login_required, fingerprint_required
from .exceptions import APIException
from ..auth import authenticate_user_from_credentials
from ..auth.verify import verify_refresh_token, get_refresh_token_from_request
from ..auth.handler import generate_refresh_token_cookie_data_from_userID
from ..utils import AuthError
from ..settings import (
    USER_GRAPHENE_OBJECT,
    REVOKE_OTHER_TOKENS_ON_AUTH_FOR_USER,
    ALLOW_USER_TO_LOGIN_ON_AUTH,
    JWT_REFRESH_TOKEN_EXPIRATION_DELTA,
    CHOWKIDAR_GAUTH_CALLBACK
)
from ..utils.settings import import_string


def revoke_other_tokens(userID, request) -> None:
    refreshToken = request.COOKIES["JWT_REFRESH_TOKEN"] if 'JWT_REFRESH_TOKEN' in request.COOKIES else None
    RefreshToken.objects.filter(
        user_id=userID, revoked__isnull=True
    ).exclude(token=refreshToken).update(
        revoked=timezone.now()
    )


class UserSession(graphene.ObjectType):
    isActive = graphene.Boolean()
    userAgent = graphene.String()
    token = graphene.String()
    ip = graphene.String()
    issued = graphene.String()
    revoked = graphene.String()

    def resolve_isActive(self, info):
        return (
            self.revoked is None
            and self.issued + JWT_REFRESH_TOKEN_EXPIRATION_DELTA > timezone.now()
        )

    def resolve_issued(self, info):
        if self.issued:
            to_tz = timezone.get_default_timezone()
            return self.issued.astimezone(to_tz).isoformat()

    def resolve_revoked(self, info):
        if self.revoked:
            to_tz = timezone.get_default_timezone()
            return self.revoked.astimezone(to_tz).isoformat()


class AuthQueries(graphene.ObjectType):
    mySessions = graphene.List(
        UserSession,
        description="View sessions of the current user",
        offset=graphene.Int(),
        count=graphene.Int()
    )

    @fingerprint_required
    def resolve_mySessions(self, info, offset=0, count=10):
        return RefreshToken.objects.filter(
            user_id=info.context.userID
        ).order_by('-revoked', '-issued')[offset:offset+count]


class AuthenticatedUser(graphene.ObjectType):
    id = graphene.ID()
    username = graphene.String()


class GenerateTokenResponse(graphene.ObjectType):
    success = graphene.Boolean()
    user = graphene.Field(USER_GRAPHENE_OBJECT)


class GenerateSocialTokenResponse(GenerateTokenResponse, graphene.ObjectType):
    social = graphene.JSONString()


class AuthenticateUser(graphene.Mutation, description='Authenticate a user using password'):
    class Arguments:
        email = graphene.String(required=False, description="Email address of the user")
        username = graphene.String(required=False, description="Username of the user")
        password = graphene.String(required=True, description="Password of the user")

    Output = GenerateTokenResponse

    def mutate(self, info, password, email=None, username=None):
        try:
            user = authenticate_user_from_credentials(password=password, email=email, username=username)

            if not import_string(ALLOW_USER_TO_LOGIN_ON_AUTH)(user):
                raise AuthError('User not allowed to login', code='FORBIDDEN')

            if import_string(REVOKE_OTHER_TOKENS_ON_AUTH_FOR_USER)(user):
                revoke_other_tokens(userID=user.id, request=info.context)

            return {"success": True, "user": user}
        except AuthError as e:
            raise e


class LogoutUser(graphene.Mutation, description='Logout a user'):

    Output = graphene.Boolean

    @login_required
    def mutate(self, info):
        # functions are handled in respond_handling_authentication()
        return True


class RevokeToken(graphene.Mutation, description='Revoke a given refresh token of user'):
    class Arguments:
        token = graphene.String(required=True, description="Token to be revoked")

    Output = graphene.Boolean

    @fingerprint_required
    def mutate(self, info, token):
        try:
            RefreshToken.objects.get(
                user_id=info.context.userID, token=token
            ).delete()
            return True
        except RefreshToken.DoesNotExist:
            raise APIException(message='Invalid Refresh Token', code='INVALID_TOKEN')
        except Exception:
            raise APIException(message='Could not revoke Refresh Token', code='FAILED')


class RevokeOtherTokens(graphene.Mutation,  description='Revoke all other refresh tokens of user except the current one'):

    Output = graphene.Boolean

    @fingerprint_required
    def mutate(self, info):
        revoke_other_tokens(userID=info.context.userID, request=info.context)
        return True


class AuthMutations(graphene.ObjectType):
    authenticateUser = AuthenticateUser.Field()
    logoutUser = LogoutUser.Field()
    revokeToken = RevokeToken.Field()
    revokeOtherTokens = RevokeOtherTokens.Field()


class SocialAuth(graphene.Mutation, description='Authenticate a user using social auth provider'):
    class Arguments:
        accessToken = graphene.String(required=True, description='Access Token from Client')
        provider = graphene.String(required=True, description='Auth Provider')

    Output = GenerateSocialTokenResponse

    def mutate(self, info, accessToken, provider):
        try:
            from social_core.exceptions import MissingBackend
            from social_django.views import _do_login
            from social_django.utils import load_backend, load_strategy
        except ImportError:
            raise AuthError(
                'social_django and social_core libraries required for supporting social auth not installed',
                code='LIBRARY_MISSING'
            )
        try:
            strategy = load_strategy(info.context)
            backend = load_backend(strategy, provider, redirect_uri=None)
        except MissingBackend:
            raise AuthError('Auth Provider Not Supported', code='INVALID_PROVIDER')

        user = backend.do_auth(accessToken, user=None)
        _do_login(backend, user, user.social_user)

        if not import_string(ALLOW_USER_TO_LOGIN_ON_AUTH)(user):
            raise AuthError('User not allowed to login', code='FORBIDDEN')

        if import_string(REVOKE_OTHER_TOKENS_ON_AUTH_FOR_USER)(user):
            revoke_other_tokens(userID=user.id, request=info.context)

        return {"success": True, "user": user.__dict__, "social": user.social_user }


class GAuth(graphene.Mutation, description='Authenticate a user using google identity services'):
    class Arguments:
        accessToken = graphene.String(required=True, description='Access Token from Client')

    Output = GenerateSocialTokenResponse

    def mutate(self, info, accessToken):
        try:
            from google.oauth2 import id_token
            from google.auth.transport import requests
            from google.auth.exceptions import GoogleAuthError
        except ImportError:
            raise AuthError(
                'google oauth2 not installed',
                code='LIBRARY_MISSING'
            )

        from ..settings import GOOGLE_AUTH_CLIENT_ID

        try:
            authObj = id_token.verify_oauth2_token(
                accessToken,
                requests.Request(),
                GOOGLE_AUTH_CLIENT_ID,
                clock_skew_in_seconds=2
            )
        except GoogleAuthError:
            raise AuthError('Invalid access token', code='INVALID_TOKEN')

        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            user = User.objects.get(email=authObj['email'])
        except User.DoesNotExist:
            user = User.objects.create_user(
                email=authObj['email'],
                username=authObj['email'],
                first_name=authObj['given_name'],
                last_name=authObj['family_name'],
            )

        import_string(CHOWKIDAR_GAUTH_CALLBACK)(authObj, user)

        if not import_string(ALLOW_USER_TO_LOGIN_ON_AUTH)(user):
            raise AuthError('User not allowed to login', code='FORBIDDEN')

        if import_string(REVOKE_OTHER_TOKENS_ON_AUTH_FOR_USER)(user):
            revoke_other_tokens(userID=user.id, request=info.context)

        return {"success": True, "user": user.__dict__}


class RefreshTokenResponse(graphene.ObjectType):
    refreshToken = graphene.String()


class GetRefreshToken(graphene.Mutation, description='Authenticate a user using password and return a refresh token'):
    class Arguments:
        email = graphene.String(description="Email address of the user")
        username = graphene.String(description="Username of the user")
        password = graphene.String(description="Password of the user")

    Output = RefreshTokenResponse

    def mutate(self, info, password=None, email=None, username=None):
        try:
            request = info.context
            try:
                refreshToken = get_refresh_token_from_request(request)
                user = refreshToken.user
            except AuthError:
                user = authenticate_user_from_credentials(password=password, email=email, username=username)

                if not import_string(ALLOW_USER_TO_LOGIN_ON_AUTH)(user):
                    raise AuthError('User not allowed to login', code='FORBIDDEN')

                if import_string(REVOKE_OTHER_TOKENS_ON_AUTH_FOR_USER)(user):
                    revoke_other_tokens(userID=user.id, request=info.context)

            data = generate_refresh_token_cookie_data_from_userID(userID=user.id, request=info.context)
            return RefreshTokenResponse(refreshToken=data['token'])
        except AuthError as e:
            raise e


class SetRefreshToken(graphene.Mutation, description='Authenticate a user using password'):
    class Arguments:
        token = graphene.String(required=True, description='Existing Refresh Token')

    Output = GenerateTokenResponse

    def mutate(self, info, token):
        try:
            from datetime import timedelta
            rt = verify_refresh_token(token)
            if timezone.now() - rt.issued > timedelta(minutes=2):
                raise AuthError('This refresh token can no longer be used to set token cookie', code='FORBIDDEN')
            user = rt.user

            if not import_string(ALLOW_USER_TO_LOGIN_ON_AUTH)(user):
                raise AuthError('User not allowed to login', code='FORBIDDEN')

            if import_string(REVOKE_OTHER_TOKENS_ON_AUTH_FOR_USER)(user):
                revoke_other_tokens(userID=user.id, request=info.context)

            return {"success": True, "user": user}
        except AuthError as e:
            raise e


class RefreshTokenMutations(graphene.ObjectType):
    getRefreshToken = GetRefreshToken.Field()
    setRefreshToken = SetRefreshToken.Field()


class SocialAuthMutations(graphene.ObjectType):
    socialAuth = SocialAuth.Field()
    gAuth = GAuth.Field()


__all__ = [
    'AuthQueries',
    'AuthMutations',
    'RefreshTokenMutations',
    'SocialAuthMutations'
]
