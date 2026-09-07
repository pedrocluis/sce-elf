use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("binary parse error: {0}")]
    Parse(#[from] binrw::Error),
    /// The image has no segment of the type a lookup asked for.
    #[error("image has no {0} segment")]
    MissingSegment(&'static str),
    #[error("image has no program header at index {0}")]
    NoSuchSegment(usize),
    /// In a SELF, every program header's contents are supposed to be provided
    /// by a "blocked" SELF segment whose id is the program header's index.
    #[error("no SELF segment provides the contents of program header {0}")]
    UnmappedSegment(usize),
    /// The bytes exist but are still wrapped in a transform we can't undo yet.
    #[error("SELF segment {index} is {reason}; reading its contents is not supported yet")]
    OpaqueSegment { index: usize, reason: &'static str },
    /// A table's offset and size run past the end of the region holding it.
    #[error(
        "{what} in {region}: offset {offset:#x} + {size:#x} bytes exceeds the {limit:#x} available"
    )]
    OutOfBounds {
        what: &'static str,
        region: &'static str,
        offset: u64,
        size: u64,
        limit: u64,
    },
    #[error("{what} entry size {size:#x} is too small (need at least {minimum:#x})")]
    BadEntrySize {
        what: &'static str,
        size: u64,
        minimum: u64,
    },
    /// A PS5 dynamic tag pointed at an address no loadable segment covers.
    #[error("no loadable segment contains virtual address {0:#x}")]
    UnmappedAddress(u64),
    #[error("string table offset {0:#x} is not a NUL-terminated UTF-8 string")]
    BadString(u64),
}

pub type Result<T> = std::result::Result<T, Error>;
