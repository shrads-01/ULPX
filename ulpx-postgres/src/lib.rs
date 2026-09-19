use serde::Serialize;
use sqlx::{PgPool, Row};
use std::time::UNIX_EPOCH;
use ulpx_replay::interpretation::{ComponentConfig, Interpretation, InterpretationId};

#[derive(Debug, thiserror::Error)]
pub enum PostgresError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Identity generation error: {0}")]
    Identity(String),
    #[error("Frame index overflow: {0}")]
    FrameIndexOverflow(usize),
}

/// A relational repository for storing interpretation metadata.
pub trait InterpretationRepository: Send + Sync {
    /// Initializes the database schema.
    #[allow(async_fn_in_trait)]
    async fn initialize_schema(&self) -> Result<(), PostgresError>;

    /// Persists an interpretation and its metadata.
    /// This operation is fully transactional and idempotent by InterpretationId.
    #[allow(async_fn_in_trait)]
    async fn save_interpretation(
        &self,
        interpretation: &Interpretation,
    ) -> Result<(), PostgresError>;

    /// Queries interpretations that contain a specific entity.
    #[allow(async_fn_in_trait)]
    async fn query_entity_interpretations(
        &self,
        entity_type: &str,
        entity_value: &str,
    ) -> Result<Vec<String>, PostgresError>;

    /// Checks if a specific interpretation has been stored.
    #[allow(async_fn_in_trait)]
    async fn has_interpretation(&self, id: &InterpretationId) -> Result<bool, PostgresError>;
}

pub struct PostgresInterpretationRepository {
    pool: PgPool,
}

impl PostgresInterpretationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// Helper structs for JSONB serialization
#[derive(Serialize)]
struct ComponentConfigJson {
    id: String,
    version: String,
}

impl From<&ComponentConfig> for ComponentConfigJson {
    fn from(c: &ComponentConfig) -> Self {
        Self {
            id: c.id.clone(),
            version: c.version.clone(),
        }
    }
}

impl InterpretationRepository for PostgresInterpretationRepository {
    async fn initialize_schema(&self) -> Result<(), PostgresError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS pipeline_configurations (
                config_hash TEXT PRIMARY KEY,
                framer_id TEXT NOT NULL,
                framer_version TEXT NOT NULL,
                mapper_id TEXT NOT NULL,
                mapper_version TEXT NOT NULL,
                parser_registry_json JSONB NOT NULL,
                inference_detectors_json JSONB NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS interpretations (
                interpretation_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                config_hash TEXT NOT NULL REFERENCES pipeline_configurations(config_hash),
                created_at_ns TEXT NOT NULL,
                integrity_verified BOOLEAN NOT NULL,
                integrity_error_json JSONB,
                trailing_frame_error_json JSONB
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS interpretation_frames (
                interpretation_id TEXT NOT NULL REFERENCES interpretations(interpretation_id) ON DELETE CASCADE,
                frame_index INTEGER NOT NULL,
                parser_id TEXT,
                parser_version TEXT,
                parser_outcome TEXT NOT NULL,
                inference_decision_json JSONB,
                PRIMARY KEY (interpretation_id, frame_index)
            );
            "#
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS entity_edges (
                interpretation_id TEXT NOT NULL REFERENCES interpretations(interpretation_id) ON DELETE CASCADE,
                frame_index INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                entity_value TEXT NOT NULL,
                role TEXT NOT NULL,
                confidence TEXT NOT NULL,
                provenance_json JSONB NOT NULL,
                PRIMARY KEY (interpretation_id, frame_index, entity_type, entity_value, role)
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_entity_edges_val ON entity_edges(entity_type, entity_value);
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn save_interpretation(
        &self,
        interpretation: &Interpretation,
    ) -> Result<(), PostgresError> {
        let mut tx = self.pool.begin().await?;

        // Retrieve domain identity for the configuration
        let config_hash = interpretation
            .pipeline_config
            .configuration_identity()
            .map_err(PostgresError::Identity)?
            .to_string();

        let interp_id_str = interpretation.id.0.to_string();
        let event_id_str = interpretation.source_event_id.as_str();

        // 1. Pipeline Configuration (Idempotent)
        let parser_reg_json = serde_json::to_value(
            interpretation
                .pipeline_config
                .parser_registry
                .iter()
                .map(ComponentConfigJson::from)
                .collect::<Vec<_>>(),
        )?;
        let inference_det_json =
            serde_json::to_value(&interpretation.pipeline_config.inference_detectors)?;

        sqlx::query(
            r#"
            INSERT INTO pipeline_configurations (
                config_hash, framer_id, framer_version, mapper_id, mapper_version,
                parser_registry_json, inference_detectors_json
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (config_hash) DO NOTHING
        "#,
        )
        .bind(&config_hash)
        .bind(&interpretation.pipeline_config.framer.id)
        .bind(&interpretation.pipeline_config.framer.version)
        .bind(&interpretation.pipeline_config.mapper.id)
        .bind(&interpretation.pipeline_config.mapper.version)
        .bind(&parser_reg_json)
        .bind(&inference_det_json)
        .execute(&mut *tx)
        .await?;

        // 2. Events projection (Idempotent stub)
        sqlx::query(
            r#"
            INSERT INTO events (event_id) VALUES ($1)
            ON CONFLICT (event_id) DO NOTHING
        "#,
        )
        .bind(event_id_str)
        .execute(&mut *tx)
        .await?;

        // 3. Interpretation (Idempotent by interpretation_id)
        let created_at_ns = interpretation
            .created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string();

        let integrity_error_json = match &interpretation.integrity_error {
            Some(err) => Some(serde_json::to_value(format!("{:?}", err))?),
            None => None,
        };

        let trailing_error_json = match &interpretation.trailing_frame_error {
            Some(err) => Some(serde_json::to_value(format!("{:?}", err))?),
            None => None,
        };

        let result = sqlx::query(
            r#"
            INSERT INTO interpretations (
                interpretation_id, event_id, config_hash, created_at_ns,
                integrity_verified, integrity_error_json, trailing_frame_error_json
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (interpretation_id) DO NOTHING
        "#,
        )
        .bind(&interp_id_str)
        .bind(event_id_str)
        .bind(&config_hash)
        .bind(&created_at_ns)
        .bind(interpretation.integrity_verified)
        .bind(&integrity_error_json)
        .bind(&trailing_error_json)
        .execute(&mut *tx)
        .await?;

        // If rows_affected == 0, this interpretation was already persisted.
        if result.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(());
        }

        // 4. Interpretation Frames
        for frame in &interpretation.frames {
            let (parser_id, parser_version) = match &frame.execution.parser_used {
                Some(p) => (Some(p.id.clone()), Some(p.version.clone())),
                None => (None, None),
            };

            let parser_outcome = match &frame.parser_outcome {
                ulpx_replay::ParserOutcome::Success(_) => "Success",
                ulpx_replay::ParserOutcome::Failed(_) => "Failed",
                ulpx_replay::ParserOutcome::Abstained => "Abstained",
            };

            let inference_json = match &frame.execution.inference {
                ulpx_replay::interpretation::InferenceExecution::NotInvoked => None,
                _ => Some(serde_json::to_value(format!(
                    "{:?}",
                    frame.execution.inference
                ))?),
            };

            let frame_index_db = i32::try_from(frame.frame_index)
                .map_err(|_| PostgresError::FrameIndexOverflow(frame.frame_index))?;

            sqlx::query(
                r#"
                INSERT INTO interpretation_frames (
                    interpretation_id, frame_index, parser_id, parser_version,
                    parser_outcome, inference_decision_json
                ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            )
            .bind(&interp_id_str)
            .bind(frame_index_db)
            .bind(&parser_id)
            .bind(&parser_version)
            .bind(parser_outcome)
            .bind(&inference_json)
            .execute(&mut *tx)
            .await?;
        }

        let entity_observations = ulpx_entity::resolution::resolve_interpretation(interpretation);
        for obs in entity_observations {
            let frame_index_db = i32::try_from(obs.frame_index)
                .map_err(|_| PostgresError::FrameIndexOverflow(obs.frame_index))?;
            let entity_type_str = format!("{:?}", obs.node.entity_type);
            let role_str = format!("{:?}", obs.role);
            let confidence_str = format!("{:?}", obs.confidence);
            let provenance_json = serde_json::to_value(&obs.provenance)?;

            sqlx::query(
                r#"
                INSERT INTO entity_edges (
                    interpretation_id, frame_index, entity_type, entity_value, role, confidence, provenance_json
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
                "#
            )
            .bind(&interp_id_str)
            .bind(frame_index_db)
            .bind(entity_type_str)
            .bind(obs.node.value)
            .bind(role_str)
            .bind(confidence_str)
            .bind(&provenance_json)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn query_entity_interpretations(
        &self,
        entity_type: &str,
        entity_value: &str,
    ) -> Result<Vec<String>, PostgresError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT interpretation_id
            FROM entity_edges
            WHERE entity_type = $1 AND entity_value = $2
            ORDER BY interpretation_id
            "#,
        )
        .bind(entity_type)
        .bind(entity_value)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| r.get("interpretation_id"))
            .collect())
    }

    async fn has_interpretation(&self, id: &InterpretationId) -> Result<bool, PostgresError> {
        let id_str = id.0.to_string();
        let exists: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(SELECT 1 FROM interpretations WHERE interpretation_id = $1)
        "#,
        )
        .bind(&id_str)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists.0)
    }
}
