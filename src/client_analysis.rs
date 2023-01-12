use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientAnalysisError {
    #[error("{0}")]
    Other(String)
}