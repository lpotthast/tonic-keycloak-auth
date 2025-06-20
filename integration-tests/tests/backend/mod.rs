use crate::common::service::{
    AmIAuthenticatedRequest, AmIAuthenticatedResponse, WhoAmIRequest, WhoAmIResponse,
    am_i_authenticated_service_server, who_am_i_service_server,
};
use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tonic::transport::Server;
use tonic::{Request, Response, Status, async_trait};
use tonic_keycloak_auth::decode::ProfileAndEmail;
use tonic_keycloak_auth::{
    KeycloakAuthStatus, PassthroughMode,
    decode::KeycloakToken,
    instance::{KeycloakAuthInstance, KeycloakConfig},
    interceptor::KeycloakAuthInterceptor,
};
use tonic_middleware::InterceptorFor;
use url::Url;

pub async fn start_tonic_backend(keycloak_url: Url, realm: String) -> JoinHandle<()> {
    let keycloak_auth_instance = Arc::new(KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(keycloak_url)
            .realm(realm)
            .build(),
    ));

    let keycloak_auth_interceptor_block =
        KeycloakAuthInterceptor::<Role, ProfileAndEmail>::builder()
            .instance(keycloak_auth_instance.clone())
            .passthrough_mode(PassthroughMode::Block)
            .expected_audiences(vec![String::from("account")])
            .persist_raw_claims(false)
            .build();

    let keycloak_auth_interceptor_pass =
        KeycloakAuthInterceptor::<Role, ProfileAndEmail>::builder()
            .instance(keycloak_auth_instance)
            .passthrough_mode(PassthroughMode::Pass)
            .expected_audiences(vec![String::from("account")])
            .persist_raw_claims(false)
            .build();

    let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

    let server_jh = tokio::spawn(async move {
        tracing::info!("Serving test backend...");
        Server::builder()
            .add_service(InterceptorFor::new(
                who_am_i_service_server::WhoAmIServiceServer::new(WhoAmIService),
                keycloak_auth_interceptor_block,
            ))
            .add_service(InterceptorFor::new(
                am_i_authenticated_service_server::AmIAuthenticatedServiceServer::new(
                    AmIAuthenticatedService,
                ),
                keycloak_auth_interceptor_pass,
            ))
            .serve(addr)
            .await
            .expect("Server to start successfully");
        tracing::info!("Test backend stopped!");
    });

    server_jh
}

struct WhoAmIService;

#[async_trait]
impl who_am_i_service_server::WhoAmIService for WhoAmIService {
    async fn who_am_i(
        &self,
        request: Request<WhoAmIRequest>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        // NOTE: We directly access the `KeycloakToken` here, which we can assume to be present
        // as the interceptor was configured to use mode `Block`!
        // The "unauthenticated" case was already handled for us (through a rejection).
        let token = request.extensions().get::<KeycloakToken<Role>>().unwrap();

        Ok(WhoAmIResponse {
            keycloak_uuid: uuid::Uuid::try_parse(&token.subject)
                .expect("uuid")
                .to_string(),
            keycloak_username: token.extra.profile.preferred_username.clone(),
            token_valid_for_seconds: (token.expires_at - time::OffsetDateTime::now_utc())
                .whole_seconds(),
        }
        .into())
    }
}

struct AmIAuthenticatedService;

#[async_trait]
impl am_i_authenticated_service_server::AmIAuthenticatedService for AmIAuthenticatedService {
    async fn am_i_authenticated(
        &self,
        request: Request<AmIAuthenticatedRequest>,
    ) -> Result<Response<AmIAuthenticatedResponse>, Status> {
        // NOTE: We check `KeycloakAuthStatus` here, which will only be set when the interceptor
        // is configured to use mode `Pass`! We basically have to handle the "unauthenticated"
        // case ourselves here.
        let auth_status = request
            .extensions()
            .get::<KeycloakAuthStatus<Role, ProfileAndEmail>>()
            .unwrap();

        match auth_status {
            KeycloakAuthStatus::Success(_) => Ok(AmIAuthenticatedResponse {
                authenticated: true,
                message: "You are authenticated.".to_string(),
            }
            .into()),
            KeycloakAuthStatus::Failure(_) => Ok(AmIAuthenticatedResponse {
                authenticated: false,
                message: "You are not authenticated.".to_string(),
            }
            .into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Role {
    Administrator,
    Unknown(String),
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Administrator => f.write_str("Administrator"),
            Role::Unknown(unknown) => f.write_fmt(format_args!("Unknown role: {unknown}")),
        }
    }
}

impl tonic_keycloak_auth::role::Role for Role {}

impl From<String> for Role {
    fn from(value: String) -> Self {
        match value.as_ref() {
            "administrator" => Role::Administrator,
            _ => Role::Unknown(value),
        }
    }
}
