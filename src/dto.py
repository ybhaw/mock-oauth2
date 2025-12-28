from typing import NotRequired, TypedDict


class ErrorResponse(TypedDict):
    error: str
    error_description: NotRequired[str]


class ClientRegistrationResponse(TypedDict):
    client_id: str
    client_secret: str
    name: str


class TokenResponse(TypedDict):
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: NotRequired[str]


class UserInfoResponse(TypedDict):
    sub: str
    preferred_username: NotRequired[str]
    email: NotRequired[str]
    email_verified: NotRequired[bool]


class OAuthMetadataResponse(TypedDict):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str
    userinfo_endpoint: str
    response_types_supported: list[str]
    grant_types_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    scopes_supported: list[str]
