# Chowkidar

A simple, flexible JWT authentication plugin for your Django Strawberry GraphQL APIs.

## Installation

1. Install the package from PyPI:

```bash
pip install chowkidar-strawberry
```

2. Add `chowkidar_strawberry` to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    "chowkidar",
]
```

3. Add `chowkidar.extensions.JWTAuthExtension` to your strawberry schema extensions:-

```python
from chowkidar.extension import JWTAuthExtension

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[JWTAuthExtension],
)
```

4. Wrap your Strawberry GraphQL view with `chowkidar.view.auth_enabled_view`:

```python
from chowkidar.view import auth_enabled_view

urlpatterns = [
  ...
  path(
      "graphql/",
      auth_enabled_view(
          GraphQLView.as_view(schema=schema, graphiql=settings.DEBUG)
      )
  ),
]
```

5. Create a Refresh Token Model inheriting the `chowkidar.models.AbstractRefreshToken` abstract model:

```python
class RefreshToken(AbstractRefreshToken, models.Model):
    pass
```

(do not forget run to `python manage.py makemigrations` and `python manage.py migrate`)

6. Implement Mutations for `login` and `logout` with `issue_tokens_on_login` and `revoke_tokens_on_logout` respectively:

```python
import strawberry
from chowkidar.wrappers import issue_tokens_on_login, revoke_tokens_on_logout

@strawberry.type
class AuthMutations:
  
  @strawberry.mutation
  @issue_tokens_on_login
  def login(self, info, username: str, password: str) -> bool:
      user = authenticate(username=username, password=password)
      if user is None:
          raise Exception("Invalid username or password")
      
      # Set LOGIN_USER with the authenticated user's object, in case of successful authentication
      # else, set LOGIN_USER to None
      info.context.LOGIN_USER = user
      
      return True
  
  @strawberry.mutation
  @revoke_tokens_on_logout
  def logout(self, info) -> bool:
      # Set info.context.LOGIN_USER to True for logging out the user
      info.context.LOGOUT_USER = True
      
      return True
```

All your resolvers will now get the following parameters from `info.context` -
 - `info.context.userID` - ID of the requesting user, None if not logged-in 
 - `info.context.refreshToken`- Refresh token string of the requesting user, None if not logged-in

## Decorators

You can use these decorators

1. `@login_required` - wrap your resolver with this decorator to ensure the resolver is called only for logged-in users.
    
```python
from chowkidar.decorators import login_required

@strawberry.type
class Query:
    
    @strawberry.field
    @login_required
    def movies(self, info) -> List[MovieType]:
        return Movie.objects.all()
```

2. `@resolve_user` - wrap this around your resolver to obtain `User` model instance of the requesting user at `info.context.user`. Hits the Database. Will throw an exception if the user is not logged-in.

```python
from chowkidar.decorators import resolve_user

@strawberry.type
class Mutation:
    
    @strawberry.mutation
    @resolve_user
    def create_movie(self, name: str, info) -> List[MovieType]:
        if not info.context.user.is_superuser:
            raise Exception("Only superusers can create movies")
        
        # Note: Like you see here, for most queryset operations you can use - user_id=info.context.userID, without needing any decorator or hitting the DB.
        return Movie.objects.create(name=name, user_id=info.context.userID)  

```

## Tracking IP Address & User Agent in Refresh Token

```python
class RefreshToken(AbstractRefreshToken, models.Model):
  ip = models.GenericIPAddressField(null=True, blank=True)
  userAgent = models.CharField(max_length=255, null=True, blank=True)
  
  def process_request_before_save(self, request: HttpRequest):
      # set IP from the request
      from ipware import get_client_ip
      ip, is_routable = get_client_ip(request)
      self.ip = ip
      
      # set user agent from the request
      agent = None
      if "User-Agent" in request.headers:
          agent = request.headers["user-agent"]
      self.userAgent = agent
```

## Settings

Here are the available settings -

```
REFRESH_TOKEN_MODEL = None # Required, a model that implements chowkidar.models.AbstractRefreshToken

JWT_REFRESH_TOKEN_N_BYTES: int = 20

# Expiry Settings

JWT_ACCESS_TOKEN_EXPIRATION_DELTA: timedelta = timezone.timedelta(seconds=60)
JWT_REFRESH_TOKEN_EXPIRATION_DELTA: timedelta = timezone.timedelta(seconds=60 * 60 * 24 * 7)

# Cookie Settings

JWT_ACCESS_TOKEN_COOKIE_NAME: str = 'JWT_ACCESS_TOKEN'
JWT_REFRESH_TOKEN_COOKIE_NAME: str = 'JWT_REFRESH_TOKEN'

JWT_COOKIE_DOMAIN: str = None
JWT_COOKIE_SAME_SITE: ['Lax', 'Strict', 'None'] = "Lax"
JWT_COOKIE_SECURE: bool = False
JWT_COOKIE_HTTP_ONLY: bool = True


# JWT Settings
JWT_SECRET_KEY: str = settings.SECRET_KEY
)
JWT_PUBLIC_KEY: str = None
JWT_PRIVATE_KEY: str = None

JWT_ALGORITHM: str = "HS256"
JWT_LEEWAY: int = 0
JWT_ISSUER: str = None

```

## How it Works?

- Uses short-lived stateless JWT Access Token set as cookie to authenticate users. An additional, long-running stateful 
  JWT Refresh Token, that is recorded in RefreshToken model, is also generated to automatically to allow refreshing / 
  generating new access token when expired. This process is fully managed automatically at the backend. For issuing
  new access token using a existing refresh token, the refresh token is validated against the DB. For all other requests,
  the DB is not hit, but access key is simply validated against its key.
- `settings.py` enlists various configuration options for this plugin. The default values are set to work out of the box
  with minimal configuration. You can override these values in your project's `settings.py` to customize the behavior.
- Uses a [custom Strawberry Extension](https://strawberry.rocks/docs/guides/extensions) to read JWT cookies from the 
  request, for validation, and auto issuing new access token using refresh token when available. Also sets up 
  `info.context.userID` for easy access to the authenticated user's ID in resolvers. This extension is valid throughout
  the resolving period of the GraphQL request, although auth is processed before actual query execution. This is defined 
  in `extensions.py`.
- Uses a wrapper function that wraps the GraphQLView to manage cookies. Data for the cookies is sent to this function
  via setting custom attribute in `request` object from `extensions.py`. This function executes after GraphQL has been
  fully processed and http response is ready. This is defined in `view.py`.
- Consumer applications can custom write login/logout mutations, by wrapping those with `@issue_tokens_on_login` and 
  `@revoke_tokens_on_logout` decorators. These are defined in `wrappers.py`
- Consumer APIs can decorate auth requiring resolvers with `@login_required` (or `@resolve_user`), as well as get 
   get the ID of the requesting user from `info.context.userID`. The decorators are defined in `decorators.py`.

## Acknowledgement

This project is inspired by django-graphql-jwt & django-graphql-social-auth by flavors.

## Contribution

Contributions are welcome. Please open an issue or a PR.

## License

This project is licensed under the [GNU General Public License V3](LICENSE).

Made by [Traboda](https://github.com/traboda/chowkidar) with ❤️ in India 🇮🇳.