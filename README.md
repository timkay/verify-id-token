Just about every web app needs authentication. Lots of providers offer authentication services, including:

* Cloud providers (e.g., Google Auth/Firebase Auth, AWS Cognito, etc.)
* Identity providers (e.g., Okta/auth0)

The process is simple: the web app delegates authentication to an authentication provider.
The authentication providers interacts with the users via some user interface and, upon successful authentication, provides an id-token to the web app.
The web app then interacts with the app's API, which provides services to the app on behalf of the user that the id-token identifies.
The id-token provides proof to the API that the user is who they claim to be.

The id-token has three parts: header, payload, and signature.
The header and signature contain information used to verify the id-token. The payload contains information about the user's identity. It looks like this:

```
{
  aud: "nicework-62cb1",
  auth_time: 1713930400,
  email: "timkay@not.com",
  email_verified: true,
  exp: 1713935563,
  firebase: {identities: {…}, sign_in_provider: 'password'},
  iat: 1713931963,
  iss: "https://securetoken.google.com/nicework-62cb1",
  name: "Tim Kay",
  sub: "yRi6aaKnUvh17uzWMPbtOdwN6Y72",
  user_id: "yRi6aaKnUvh17uzWMPbtOdwN6Y72",
}
```

How does the API know that the id-token is legitimate. Somebody could create an id-token with a payload that claims a certain identity.
How does the server know that the id-token is bogus?

The answer is straight forward. The identity provider signs the id-token using their private key. They also publish their public key at a known URL. The API retrieves the public key, uses it to verify the 
