use super::types::ErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

pub(super) type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub(super) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub(super) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    pub(super) fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    pub(super) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    pub(super) fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

pub(super) fn map_storage_write_error(error: anyhow::Error) -> ApiError {
    if let Some(sqlx_error) = error.downcast_ref::<sqlx::Error>() {
        if let Some(database_error) = sqlx_error.as_database_error() {
            if database_error.is_unique_violation() {
                return ApiError::conflict(database_error.message().to_string());
            }
            if database_error.is_foreign_key_violation() {
                return ApiError::bad_request(database_error.message().to_string());
            }
        }
    }

    ApiError::internal(error)
}
