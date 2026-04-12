use axum::{
    routing::{get, patch},
    Router,
};

mod crud;
mod ideas;
mod plugins;

use super::*;
use crud::*;
use ideas::*;
use plugins::*;

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/rules", get(list_rules_handler).post(create_rule_handler))
        .route(
            "/rule-action-plugins",
            get(list_rule_action_plugins_handler),
        )
        .route(
            "/rule-action-plugins/install",
            axum::routing::post(install_rule_action_plugin_handler),
        )
        .route(
            "/rule-action-plugins/:plugin_id",
            axum::routing::patch(update_rule_action_plugin_handler)
                .delete(delete_rule_action_plugin_handler),
        )
        .route(
            "/rule-action-plugins/upload",
            axum::routing::post(upload_rule_action_plugin_handler),
        )
        .route(
            "/rule-action-templates",
            get(list_rule_action_templates_handler),
        )
        .route(
            "/rule-action-templates/:template_id/preview",
            get(preview_rule_action_template_handler),
        )
        .route(
            "/action-idea-presets",
            get(list_action_idea_presets_handler),
        )
        .route(
            "/action-idea-presets/:idea_id",
            patch(update_action_idea_preset_handler),
        )
        .route(
            "/action-idea-presets/:idea_id/upload-gzip",
            axum::routing::post(upload_action_idea_gzip_handler),
        )
        .route(
            "/rules/:id",
            get(get_rule_handler)
                .put(update_rule_handler)
                .delete(delete_rule_handler),
        )
}
