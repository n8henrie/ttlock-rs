//! Read the Sciener/TTLock app's local sqlite database and convert it into
//! `lockData.json` entries.
//!
//! The database is opened strictly read-only. The pure column-to-[`LockData`]
//! decoding lives in [`ttlock_core::sciener`]; this module only does the sqlite
//! I/O and hands each row's raw column values to that decoder.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use ttlock_core::config::LockData;
use ttlock_core::sciener::ScienerKeyRow;

use crate::error::Result;

/// Rows without a MAC or AES key can't produce a usable lock entry, so they are
/// filtered out in SQL rather than erroring the whole import.
const QUERY: &str = "SELECT ZLOCKMAC, ZAESKEYSTR, ZADMINPS, ZLOCKKEY, ZAUTOLOCKTIME, ZRSSI \
     FROM ZKEY \
     WHERE ZLOCKMAC IS NOT NULL AND ZAESKEYSTR IS NOT NULL";

/// Open `path` read-only and convert every usable `ZKEY` row into a
/// [`LockData`] entry.
///
/// # Errors
/// Returns an error if the database cannot be opened or queried, or if a row's
/// credentials cannot be decoded.
pub fn read_sciener_db(path: &Path) -> Result<Vec<LockData>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    lock_data_from_connection(&conn)
}

/// Run the `ZKEY` query against an already-open connection and decode each row.
/// Split out from [`read_sciener_db`] so it can be tested against a synthetic
/// in-memory database.
fn lock_data_from_connection(conn: &Connection) -> Result<Vec<LockData>> {
    let mut statement = conn.prepare(QUERY)?;
    let rows = statement.query_map([], |row| {
        Ok(ScienerKeyRow {
            lock_mac: row.get(0)?,
            aes_key_csv: row.get(1)?,
            admin_ps: row.get(2)?,
            lock_key: row.get(3)?,
            auto_lock_time: row.get(4)?,
            rssi: row.get(5)?,
        })
    })?;

    let mut locks = Vec::new();
    for row in rows {
        locks.push(row?.into_lock_data()?);
    }
    Ok(locks)
}

#[cfg(test)]
mod tests {
    use super::{Connection, lock_data_from_connection, read_sciener_db};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    // Fabricated, non-secret fixtures — never real database values. The
    // credential is the project's public sample (decodes to 659_525_046).
    const PUBLIC_CREDENTIAL: &str = "NjgsNjYsNjUsNzcsNjUsNzAsNjUsNjgsNjQsNjYsMTA=";
    const PUBLIC_CREDENTIAL_INT: u32 = 659_525_046;
    const FAKE_AES_CSV: &str = "00,11,22,33,44,55,66,77,88,99,aa,bb,cc,dd,ee,ff";
    const FAKE_AES_HEX: &str = "00112233445566778899aabbccddeeff";
    const FAKE_MAC: &str = "AA:BB:CC:DD:EE:FF";
    /// A second synthetic lock, for asserting that multiple rows are imported.
    const OTHER_FAKE_MAC: &str = "AA:BB:CC:DD:EE:F0";

    /// A minimal `ZKEY` table with only the columns the importer reads.
    fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "CREATE TABLE ZKEY (
                 ZLOCKMAC       TEXT,
                 ZAESKEYSTR     TEXT,
                 ZADMINPS       TEXT,
                 ZLOCKKEY       TEXT,
                 ZAUTOLOCKTIME  INTEGER,
                 ZRSSI          INTEGER
             );",
        )
    }

    fn insert_row(
        conn: &Connection,
        mac: Option<&str>,
        aes: Option<&str>,
        admin_ps: Option<&str>,
        lock_key: Option<&str>,
        auto_lock: Option<i64>,
        rssi: Option<i64>,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO ZKEY
                 (ZLOCKMAC, ZAESKEYSTR, ZADMINPS, ZLOCKKEY, ZAUTOLOCKTIME, ZRSSI)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![mac, aes, admin_ps, lock_key, auto_lock, rssi],
        )?;
        Ok(())
    }

    #[test]
    fn decodes_a_full_admin_row() -> TestResult {
        let conn = Connection::open_in_memory()?;
        create_schema(&conn)?;
        insert_row(
            &conn,
            Some(FAKE_MAC),
            Some(FAKE_AES_CSV),
            Some(PUBLIC_CREDENTIAL),
            Some(PUBLIC_CREDENTIAL),
            Some(5),
            Some(-60),
        )?;

        let locks = lock_data_from_connection(&conn)?;
        assert_eq!(locks.len(), 1);
        let lock = &locks[0];
        assert_eq!(lock.address, FAKE_MAC);
        assert_eq!(lock.private_data.aes_key.as_deref(), Some(FAKE_AES_HEX));
        assert_eq!(lock.private_data.admin_ps, Some(PUBLIC_CREDENTIAL_INT));
        assert_eq!(lock.private_data.unlock_key, Some(PUBLIC_CREDENTIAL_INT));
        assert_eq!(lock.auto_lock_time, 5);
        assert_eq!(lock.rssi, -60);
        Ok(())
    }

    #[test]
    fn decodes_multiple_rows() -> TestResult {
        let conn = Connection::open_in_memory()?;
        create_schema(&conn)?;
        insert_row(
            &conn,
            Some(FAKE_MAC),
            Some(FAKE_AES_CSV),
            Some(PUBLIC_CREDENTIAL),
            Some(PUBLIC_CREDENTIAL),
            Some(0),
            None,
        )?;
        insert_row(
            &conn,
            Some(OTHER_FAKE_MAC),
            Some(FAKE_AES_CSV),
            None,
            None,
            None,
            None,
        )?;

        let locks = lock_data_from_connection(&conn)?;
        assert_eq!(locks.len(), 2);
        // Second row has no credentials, only the AES key.
        assert_eq!(locks[1].private_data.admin_ps, None);
        assert_eq!(locks[1].private_data.unlock_key, None);
        assert_eq!(locks[1].private_data.aes_key.as_deref(), Some(FAKE_AES_HEX));
        Ok(())
    }

    #[test]
    fn skips_rows_missing_mac_or_aes() -> TestResult {
        let conn = Connection::open_in_memory()?;
        create_schema(&conn)?;
        // No MAC.
        insert_row(&conn, None, Some(FAKE_AES_CSV), None, None, None, None)?;
        // No AES key.
        insert_row(&conn, Some(FAKE_MAC), None, None, None, None, None)?;
        // One good row.
        insert_row(
            &conn,
            Some(FAKE_MAC),
            Some(FAKE_AES_CSV),
            None,
            None,
            None,
            None,
        )?;

        let locks = lock_data_from_connection(&conn)?;
        assert_eq!(locks.len(), 1);
        Ok(())
    }

    #[test]
    fn empty_table_yields_no_entries() -> TestResult {
        let conn = Connection::open_in_memory()?;
        create_schema(&conn)?;
        let locks = lock_data_from_connection(&conn)?;
        assert!(locks.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_credential_is_an_error() -> TestResult {
        let conn = Connection::open_in_memory()?;
        create_schema(&conn)?;
        insert_row(
            &conn,
            Some(FAKE_MAC),
            Some(FAKE_AES_CSV),
            Some("not-valid-base64!!"),
            None,
            None,
            None,
        )?;
        assert!(lock_data_from_connection(&conn).is_err());
        Ok(())
    }

    #[test]
    fn reads_from_a_read_only_file_without_modifying_it() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "ttlock_sciener_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir)?;
        let db_path = dir.join("sciener.sqlite");

        {
            let conn = Connection::open(&db_path)?;
            create_schema(&conn)?;
            insert_row(
                &conn,
                Some(FAKE_MAC),
                Some(FAKE_AES_CSV),
                Some(PUBLIC_CREDENTIAL),
                Some(PUBLIC_CREDENTIAL),
                Some(1),
                Some(-40),
            )?;
        }

        let before = std::fs::metadata(&db_path).and_then(|m| m.modified())?;

        let locks = read_sciener_db(&db_path)?;
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].address, FAKE_MAC);

        let after = std::fs::metadata(&db_path).and_then(|m| m.modified())?;
        assert_eq!(before, after, "read-only open must not modify the file");

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
