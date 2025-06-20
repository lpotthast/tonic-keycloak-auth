use crate::error::AuthError;
use nonempty::NonEmpty;
use std::{borrow::Cow, sync::Arc};

/// A raw (unprocessed) token (string) taken from a request.
/// This being `Cow` allows the `TokenExtractor` implementations to borrow from the request if possible.
pub type ExtractedToken<'a> = Cow<'a, str>;

/// Allows for customized strategies on how to retrieve the auth token from an tonic request.
/// This crate implements two default strategies:
///   - `AuthHeaderTokenExtractor`: Extracts the token from the `http::header::AUTHORIZATION` header.
///   - `QueryParamTokenExtractor`: Extracts the token from a query parameter (for example named "token").
///
/// Note: The current return type and caller impl does not allow to return multiple tokens from a request.
/// We may implement this feature in the future. This could allow the QueryParamTokenExtractor to extract all tokens found.
pub trait TokenExtractor: Send + Sync + std::fmt::Debug {
    fn extract<'a>(
        &self,
        request: &'a http::Request<tonic::body::Body>,
    ) -> Result<ExtractedToken<'a>, AuthError>;
}

/// Searches the auth token in the authorization header. (Authorization: `Bearer <token>`)
#[derive(Debug, Clone, Default)]
pub struct AuthHeaderTokenExtractor {}

impl TokenExtractor for AuthHeaderTokenExtractor {
    fn extract<'a>(
        &self,
        request: &'a http::Request<tonic::body::Body>,
    ) -> Result<ExtractedToken<'a>, AuthError> {
        request
            .headers()
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingAuthorizationHeader)?
            .to_str()
            .map_err(|err| AuthError::InvalidAuthorizationHeader {
                reason: err.to_string(),
            })?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingBearerToken)
            .map(Cow::Borrowed)
    }
}

pub(crate) fn extract_jwt<'a>(
    request: &'a http::Request<tonic::body::Body>,
    extractors: &NonEmpty<Arc<dyn TokenExtractor>>,
) -> Option<ExtractedToken<'a>> {
    for extractor in extractors {
        match extractor.extract(request) {
            Ok(jwt) => return Some(jwt),
            Err(err) => {
                tracing::debug!(?extractor, ?err, "Extractor failed");
            }
        }
    }
    None
}
