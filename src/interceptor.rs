extern crate alloc;
use crate::{
    KeycloakAuthStatus,
    decode::{KeycloakToken, ProfileAndEmail, RawToken, decode_and_validate, parse_raw_claims},
    error::AuthError,
    extract,
    extract::TokenExtractor,
    instance::KeycloakAuthInstance,
    role::Role,
};
use nonempty::NonEmpty;
use serde::de::DeserializeOwned;
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, sync::Arc};
use tonic::async_trait;
use tonic::codegen::http::Request;
use typed_builder::TypedBuilder;

use super::PassthroughMode;

/// Add this layer to a router to protect the contained route handlers.
/// Authentication happens by looking for the `Authorization` header on requests and parsing the contained JWT bearer token.
/// See the crate level documentation for how this layer can be created and used.
#[derive(Debug, Clone, TypedBuilder)]
pub struct KeycloakAuthInterceptor<R, Extra = ProfileAndEmail>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    #[builder(default = uuid::Uuid::now_v7(), setter(skip))]
    id: uuid::Uuid,

    #[builder(setter(into))]
    pub instance: Arc<KeycloakAuthInstance>,

    /// See `PassthroughMode` for more information.
    #[builder(default = PassthroughMode::Block)]
    pub passthrough_mode: PassthroughMode,

    /// Determine if the raw claims extracted from the JWT are persisted as an `Extension`.
    /// If you do not need access to this information, fell free to set this to false.
    #[builder(default = false)]
    pub persist_raw_claims: bool,

    /// Allowed values of the JWT 'aud' (audiences) field. Token validation will fail immediately if this is left empty!
    pub expected_audiences: Vec<String>,

    /// These roles are always required.
    /// Should a route protected by this layer be accessed by a user not having this role, an error is generated.
    /// If fine-grained role-based access management in required,
    /// leave this empty and perform manual role checks in your route handlers.
    #[builder(default = vec![], setter(into))]
    pub required_roles: Vec<R>,

    /// Specifies where the token is expected to be found.
    #[builder(default = nonempty::nonempty![Arc::new(crate::extract::AuthHeaderTokenExtractor {})])]
    pub token_extractors: NonEmpty<Arc<dyn TokenExtractor>>,

    #[builder(default=PhantomData, setter(skip))]
    phantom: PhantomData<Extra>,
}

impl<R, Extra> KeycloakAuthInterceptor<R, Extra>
where
    R: Role,
    Extra: DeserializeOwned + Clone,
{
    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    /// Allows to validate a raw keycloak token given as &str (without the "Bearer " part when taken from an authorization header).
    /// This method is helpful if you wish to validate a token which does not pass the tonic middleware
    /// or if you wish to validate a token in a different context.
    pub async fn validate_raw_token(
        &self,
        raw_token: &str,
    ) -> Result<
        (
            Option<HashMap<String, serde_json::Value>>,
            KeycloakToken<R, Extra>,
        ),
        AuthError,
    > {
        let raw_claims = decode_and_validate(
            self.instance.as_ref(),
            RawToken(raw_token),
            &self.expected_audiences,
        )
        .await?;

        parse_raw_claims::<R, Extra>(raw_claims, self.persist_raw_claims, &self.required_roles)
            .await
    }
}

#[async_trait]
impl<R, Extra> tonic_middleware::RequestInterceptor for KeycloakAuthInterceptor<R, Extra>
where
    R: Role + 'static,
    Extra: DeserializeOwned + Clone + Send + Sync + 'static,
{
    async fn intercept(
        &self,
        mut request: Request<tonic::body::Body>,
    ) -> Result<Request<tonic::body::Body>, tonic::Status> {
        tracing::debug!("Validating request...");

        if self.instance.discovery.is_pending() {
            self.instance.discovery.notified().await;
        }

        // Process the request.
        let result = match extract::extract_jwt(&request, &self.token_extractors) {
            Some(token) => self.validate_raw_token(&token).await,
            None => Err(AuthError::MissingToken),
        };

        match result {
            Ok((raw_claims, keycloak_token)) => {
                if let Some(raw_claims) = raw_claims {
                    request.extensions_mut().insert(raw_claims);
                }
                match self.passthrough_mode {
                    PassthroughMode::Block => {
                        request.extensions_mut().insert(keycloak_token);
                    }
                    PassthroughMode::Pass => {
                        request
                            .extensions_mut()
                            .insert(KeycloakAuthStatus::<R, Extra>::Success(keycloak_token));
                    }
                };
                Ok(request)
            }
            Err(err) => match self.passthrough_mode {
                PassthroughMode::Block => Err(err.to_status()),
                PassthroughMode::Pass => {
                    request
                        .extensions_mut()
                        .insert(KeycloakAuthStatus::<R, Extra>::Failure(Arc::new(err)));
                    Ok(request)
                }
            },
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use nonempty::NonEmpty;
    use url::Url;

    use crate::{
        PassthroughMode,
        extract::{AuthHeaderTokenExtractor, TokenExtractor},
        instance::{KeycloakAuthInstance, KeycloakConfig},
        interceptor::KeycloakAuthInterceptor,
    };

    #[tokio::test]
    async fn build_basic_layer() {
        let instance = KeycloakAuthInstance::new(
            KeycloakConfig::builder()
                .server(Url::parse("https://localhost:8443/").unwrap())
                .realm(String::from("MyRealm"))
                .retry((10, 2))
                .build(),
        );

        let _layer = KeycloakAuthInterceptor::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .build();
    }

    #[tokio::test]
    async fn build_full_layer() {
        let instance = KeycloakAuthInstance::new(
            KeycloakConfig::builder()
                .server(Url::parse("https://localhost:8443/").unwrap())
                .realm(String::from("MyRealm"))
                .retry((10, 2))
                .build(),
        );

        let _layer = KeycloakAuthInterceptor::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .expected_audiences(vec![String::from("account")])
            .required_roles(vec![String::from("administrator")])
            .token_extractors(NonEmpty::<Arc<dyn TokenExtractor>> {
                head: Arc::new(AuthHeaderTokenExtractor::default()),
                tail: vec![],
            })
            .build();
    }
}
