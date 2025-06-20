# tonic-keycloak-auth

Protect tonic services with a JWT emitted by Keycloak.

## Features

- tonic-middleware request interceptor that can be attached to tonic services.
- Automatic OIDC discovery.
- Forwarding only requests providing a verifiable and non-expired JWT.
- Ability to allow forwarding a failed authentication attempt to possibly handle the authentication using another
  middleware.
- Ability to access the extracted JWT data (including roles, the KC uuid, ...) in route handler function.
- Tests to check that one or more required or forbidden Keycloak realm or client roles were included in the JWT.
- Ability to access the JWT's raw claims in a handler, allowing to extract custom attributes.
- An error type implementing IntoResponse providing exact information about why authentication failed in an error
  response.
- Ability to define a custom role type from your application to which all roles are automatically parsed.

## Planned

- Ability to provide a custom type into which the token is parsed, with which non-standard JWT claims can be extracted
  without overhead.
- Allowing fine-grained control over how an `AuthError` is converted into a response. Giving the user control and the
  ability to add context, roll their own.

## Usage

This library provides `KeycloakAuthLayer`, a tower layer/service implementation that parses and validates a JWT.

See the **[Documentation](https://docs.rs/tonic-keycloak-auth)** for more detailed instructions!

```rust
enum Role {
    Administrator,
    Unknown(String),
}

pub fn protected_router(instance: KeycloakAuthInstance) -> Router {
    Router::new()
        .route("/protected", get(protected))
        .layer(
            KeycloakAuthLayer::<Role>::builder()
                .instance(instance)
                .passthrough_mode(PassthroughMode::Block)
                .build(),
        )
}

pub async fn protected(Extension(token): Extension<KeycloakToken<Role>>) -> Response {
    expect_role!(&token, Role::Administrator);

    info!("Token payload is {token:#?}");
    (
        StatusCode::OK,
        format!(
            "Hello {name} ({subject}). Your token is valid for another {valid_for} seconds.",
            name = token.extra.profile.preferred_username,
            subject = token.subject,
            valid_for = (token.expires_at - time::OffsetDateTime::now_utc()).whole_seconds()
        ),
    ).into_response()
}
```

## tonic compatibility

| tonic-keycloak-auth | tonic |
|---------------------|-------|
| 0.1                 | 0.13  |

## Development

### Tests

Run test with

    cargo test

Pass the `--nocapture` flag when developing to be able to see log/tracing output.

    cargo test -- --nocapture

### Integration tests

Make sure that Docker is running.

Run integration tests with

    cd integration-test && cargo test
