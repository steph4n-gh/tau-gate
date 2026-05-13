use std::fmt;

/// Custom error type for Tau-Gate to eliminate the dependency on 'anyhow'.
#[derive(Debug)]
pub enum GateError {
    Config(String),
    Graph(String),
    Math(String),
    IO(String),
    Telemetry(String),
    Generic(String),
}

impl std::error::Error for GateError {}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::Config(msg) => write!(f, "Configuration Error: {}", msg),
            GateError::Graph(msg) => write!(f, "Graph Error: {}", msg),
            GateError::Math(msg) => write!(f, "Math Error: {}", msg),
            GateError::IO(msg) => write!(f, "I/O Error: {}", msg),
            GateError::Telemetry(msg) => write!(f, "Telemetry Error: {}", msg),
            GateError::Generic(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// A specialized Result type for Tau-Gate operations.
pub type Result<T> = std::result::Result<T, GateError>;

/// Trait to provide context-like functionality similar to 'anyhow'.
pub trait GateContext<T> {
    fn context(self, msg: &str) -> Result<T>;
}

impl<T, E: std::fmt::Display> GateContext<T> for std::result::Result<T, E> {
    fn context(self, msg: &str) -> Result<T> {
        self.map_err(|e| GateError::Generic(format!("{}: {}", msg, e)))
    }
}

impl<T> GateContext<T> for Option<T> {
    fn context(self, msg: &str) -> Result<T> {
        self.ok_or_else(|| GateError::Generic(msg.to_string()))
    }
}

// Implement From traits for automatic conversion with the '?' operator

impl From<std::io::Error> for GateError {
    fn from(err: std::io::Error) -> Self {
        GateError::IO(err.to_string())
    }
}
