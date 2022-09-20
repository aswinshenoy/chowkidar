# Chowkidar

A simple, straight-forward JWT authentication plugin for your Django Strawberry GraphQL APIs.

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

This project is inspired by django-graphql-jwt & django-graphql-social-auth by flavors, and is loosely 
forked from its implementation. 

## License

This project is licensed under the [GNU General Public License V3](LICENSE).