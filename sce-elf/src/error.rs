use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("binary parse error: {0}")]
    Parse(#[from] binrw::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
