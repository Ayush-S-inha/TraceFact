use rusqlite::{Connection, Result};

pub fn initialize(path: &str) -> Result<Connection> {
    let connection = Connection::open(path)?;
    connection.execute_batch(include_str!("../../schema/tracefact.sql"))?;
    Ok(connection)
}
