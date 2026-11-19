# -cs3720_activity12
MOB user authentication

## Logging out

Send `POST /logout` with the current access token in the `Authorization: Bearer <token>` header. The API records the token as revoked, so subsequent protected requests reject it. The mobile app also removes the token from AsyncStorage after the API confirms logout.

Revocation records expire automatically after the JWT expiration time through MongoDB's TTL index.
