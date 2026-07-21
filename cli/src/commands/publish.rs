//! `odal publish` — publish draft passports (signs with the operator identity).

use anyhow::{Result, bail};

use crate::{
    core::{onboarding::action_node_state, passport::action_publish, types::PublishParams},
    stateless::render::render_publish_summary,
};

pub async fn run_publish(id: Option<&str>) -> Result<()> {
    let (client, cfg) = crate::http::load_client()?;

    // Fail fast (one round-trip) if the operator identity isn't complete — the
    // node would otherwise reject every passport individually at publish.
    if let Ok(state) = action_node_state(&client, &cfg).await
        && !state.operator_complete
    {
        bail!(
            "operator identity is incomplete — set it before publishing:\n  \
                 odal operator set --legal-name … --country … --address … --contact-email …"
        );
    }

    let params = PublishParams {
        id: id.map(str::to_owned),
    };
    let single = params.id.is_some();

    if !single {
        println!("Publishing draft passports...\n");
    }

    let result = action_publish(&params, &client, &cfg).await?;
    render_publish_summary(&result, single);

    if result.failed > 0 {
        anyhow::bail!("{} passport(s) failed to publish", result.failed);
    }
    Ok(())
}
