use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Core(#[from] ttlock_core::error::TtlockError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("BLE error: {0}")]
    Ble(#[from] btleplug::Error),

    #[error("MQTT client error: {0}")]
    Mqtt(#[from] rumqttc::ClientError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("no Bluetooth adapter found")]
    NoAdapter,

    #[error("target device was not found")]
    DeviceNotFound,

    #[error("TTLock write characteristic was not found")]
    WriteCharacteristicNotFound,

    #[error("TTLock notify characteristic was not found")]
    NotifyCharacteristicNotFound,

    #[error("timed out waiting for response")]
    Timeout,

    #[error("device disconnected")]
    Disconnected,
}

pub type Result<T> = std::result::Result<T, CliError>;
