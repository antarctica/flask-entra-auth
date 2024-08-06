# Flask Azure Auth Experiments

Experiment to update how access to a Flask app can be controlled using Azure/Entra ID.

## Purpose

To find a replacement for the now outdated
[Flask Azure OAuth](https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth) package.

See https://gitlab.data.bas.ac.uk/MAGIC/add-metadata-toolbox/-/issues/384 for background.

## Usage

Start server:

```
$ poetry run flask --app=flask_azure.__main__:app run --debug --port 5005
```

From [`flask_azure.http`](flask_azure.http) using PyCharm run:

- the `login.microsoftonline.com/.../devicecode` request, following the prompt to sign in with the device code
- then the `login.microsoftonline.com/.../token` request, to set an access token for use in app requests

Run the `/introspect` request from [`flask_azure.http`](flask_azure.http) using PyCharm:

- data is returned according to RFC7662

## Experiments

### Token validation

Sources:

- initially https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa
  - which checks signing key and audience (`aud`) claim
- then https://github.com/Intility/fastapi-azure-auth/blob/main/fastapi_azure_auth/auth.py#L189
  - which additionally checks `iss` claim
- then from various parts of https://github.com/AzureAD/microsoft-authentication-library-for-python/issues/147:
  - which includes clock skew (not been a problem for us inclined to omit for now)
- then from https://gitlab.data.bas.ac.uk/web-apps/flask-extensions/flask-azure-oauth/-/blob/main/src/flask_azure_oauth/tokens.py:
  - which additionally required the `sub` and `azp` claim for optionally filtering the security principle and application
  - which also exposed a leeway value with a default of 0
  - it also checked the `iat` claim but given we didn't do anything with its value, I don't think this adds anything

Summary:

- we check all standard claims (not sure about `nbf` and we ignore `iat` as we don't have a use for it)
- we additionally check the `ver` Entra specific claim is '2.0'
- we optionally additionally check the `sub` and/or `azp` claim values are allowed as per a list

## Licence

Copyright (c) 2024 UK Research and Innovation (UKRI), British Antarctic Survey (BAS).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

