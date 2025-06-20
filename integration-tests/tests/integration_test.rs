use crate::common::service::am_i_authenticated_service_client::AmIAuthenticatedServiceClient;
use crate::common::service::who_am_i_service_client::WhoAmIServiceClient;
use crate::common::service::{AmIAuthenticatedRequest, WhoAmIRequest};
use assertr::prelude::*;
use http::{Uri, header};
use keycloak::{
    KeycloakAdmin,
    types::{
        ClientRepresentation, CredentialRepresentation, RealmRepresentation, RoleRepresentation,
        RolesRepresentation, UserRepresentation,
    },
};
use keycloak_container::KeycloakContainer;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Status, async_trait};

mod backend;
mod common;
mod keycloak_container;

#[tokio::test]
async fn test_integration() {
    common::tracing::init_subscriber();

    let keycloak_container = KeycloakContainer::start().await;

    let admin_client = keycloak_container.admin_client().await;

    configure_keycloak(&admin_client).await;

    let be_jh =
        backend::start_tonic_backend(keycloak_container.url.clone(), "test-realm".to_owned()).await;

    let access_token = keycloak_container
        .perform_password_login(
            "test-user-mail@foo.bar",
            "password",
            "test-realm",
            "test-client",
        )
        .await;

    let backend_url = "http://127.0.0.1:9999";

    let channel = Channel::builder(backend_url.parse::<Uri>().unwrap())
        .connect()
        .await
        .unwrap();

    struct TokenProvider {
        access_token: String,
    }
    #[async_trait]
    impl tonic::service::Interceptor for TokenProvider {
        fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
            request.metadata_mut().insert(
                header::AUTHORIZATION.as_str(),
                MetadataValue::try_from(format!("Bearer {}", self.access_token))
                    .expect("valid metadata value"),
            );
            Ok(request)
        }
    }

    let mut unauthenticated_amiauthenticated_client =
        AmIAuthenticatedServiceClient::new(channel.clone());
    let mut authenticated_amiauthenticated_client = AmIAuthenticatedServiceClient::with_interceptor(
        channel.clone(),
        TokenProvider {
            access_token: access_token.clone(),
        },
    );

    let mut authenticated_whoami_client = WhoAmIServiceClient::with_interceptor(
        channel,
        TokenProvider {
            access_token: access_token.clone(),
        },
    );

    let am_i_authenticated_response = unauthenticated_amiauthenticated_client
        .am_i_authenticated(AmIAuthenticatedRequest {})
        .await;
    assert_that_ref(&am_i_authenticated_response).is_ok();
    let am_i_authenticated_response = am_i_authenticated_response.unwrap().into_inner();
    assert_that(am_i_authenticated_response.authenticated).is_false();
    assert_that(am_i_authenticated_response.message).is_equal_to("You are not authenticated.");

    let who_am_i_response = authenticated_whoami_client.who_am_i(WhoAmIRequest {}).await;
    assert_that_ref(&who_am_i_response).is_ok();
    let who_am_i_response = who_am_i_response.unwrap().into_inner();
    assert_that(who_am_i_response.keycloak_uuid)
        .is_equal_to("a7060488-c80b-40c5-83e2-d7000bf9738e");
    assert_that(who_am_i_response.keycloak_username).is_equal_to("test-user-mail@foo.bar");
    assert_that(who_am_i_response.token_valid_for_seconds).is_greater_than(0);

    let am_i_authenticated_response = authenticated_amiauthenticated_client
        .am_i_authenticated(AmIAuthenticatedRequest {})
        .await;
    assert_that_ref(&am_i_authenticated_response).is_ok();
    let am_i_authenticated_response = am_i_authenticated_response.unwrap().into_inner();
    assert_that(am_i_authenticated_response.authenticated).is_true();
    assert_that(am_i_authenticated_response.message).is_equal_to("You are authenticated.");

    be_jh.abort();
}

async fn configure_keycloak(admin_client: &KeycloakAdmin) {
    tracing::info!("Configuring Keycloak...");

    admin_client
        .post(RealmRepresentation {
            enabled: Some(true),
            realm: Some("test-realm".to_owned()),
            display_name: Some("test-realm".to_owned()),
            registration_email_as_username: Some(true),
            clients: Some(vec![
                // Being public and accepting direct-access-grants allows us to log in with grant type "password".
                ClientRepresentation {
                    enabled: Some(true),
                    public_client: Some(true),
                    direct_access_grants_enabled: Some(true),
                    id: Some("test-client".to_owned()),
                    ..Default::default()
                },
            ]),
            roles: Some(RolesRepresentation {
                realm: Some(vec![RoleRepresentation {
                    name: Some("developer".to_owned()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            users: Some(vec![
                // The user should be "fully set up" to allow logins!
                // No unverified mail, all required fields set (including names), no temporary password, no required pw reset action!
                UserRepresentation {
                    id: Some("a7060488-c80b-40c5-83e2-d7000bf9738e".to_owned()),
                    enabled: Some(true),
                    username: Some("test-user-mail@foo.bar".to_owned()),
                    email: Some("test-user-mail@foo.bar".to_owned()),
                    email_verified: Some(true),
                    first_name: Some("firstName".to_owned()),
                    last_name: Some("lastName".to_owned()),
                    realm_roles: Some(vec!["developer".to_owned()]),
                    credentials: Some(vec![CredentialRepresentation {
                        type_: Some("password".to_owned()),
                        value: Some("password".to_owned()),
                        temporary: Some(false),
                        ..Default::default()
                    }]),
                    required_actions: Some(vec![]),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        })
        .await
        .unwrap();
}
