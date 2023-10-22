//! Database implementation using PostgreSQL.
use crate::constants::{MAX_BLOCKS_LEN, MAX_IDENTIFIER_LEN};
use aft_crypto::password_encryption::PHC_STR_LEN;
use log::{error, trace};
use tokio;
use tokio_postgres::{Client, NoTls};

pub const DBNAME: &str = "ftdb";
pub type Result<T> = std::result::Result<T, tokio_postgres::Error>;

pub struct Database {
    client: Client,
}

impl Database {
    /// Creates a new PostgreSQL client, and moves the connection to the background.
    pub async fn new(username: &str, password: &str) -> Result<Self> {
        let (client, conn) = tokio_postgres::connect(
            format!(
                "host=localhost user={} password={} dbname={}",
                username, password, DBNAME
            )
            .as_str(),
            NoTls,
        )
        .await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!("Couldn't connect to database: {}", e);
            }
        });
        // TODO
        if client.is_closed() {}

        Ok(Database { client })
    }

    /// Creates a new table in the following template:
    /// +------------+-------------+---------------+
    /// | Identifier | Scrypt Data | Blocked users |
    /// +------------+-------------+---------------+
    /// | IDENTIFIER | SCRYPT DATA | BLOCKED USERS |
    /// +------------+-------------+---------------+
    pub async fn create_table(&mut self) -> Result<()> {
        match self.client.execute(&format!("CREATE TABLE IF NOT EXISTS clients (
            identifier varchar({}),
            scrypt varchar({}),
            blocks varchar({})
            )", MAX_IDENTIFIER_LEN, PHC_STR_LEN, MAX_BLOCKS_LEN), &[]).await {
            Ok(_) => (),
            Err(e) => panic!("{:?}", e),
        }
        Ok(())
    }

    /// Fetches scrypt data by an identifier.
    pub async fn get_scryptd_ident(&self, ident: &str) -> Result<String> {
        trace!("DB: {} wants scrypt data", ident);
        let row_ident = self.client.query_one("SELECT scrypt FROM clients WHERE identifier = $1", &[&ident]).await?;
        row_ident.try_get(0)
    }

    pub async fn add_row(&mut self, ident: &str, scryptd: &str) -> Result<bool> {
        Ok(self.client.execute("INSERT INTO clients (identifier, scrypt) VALUES ($1, $2)", &[&ident, &scryptd]).await? > 0)
    }

    pub async fn add_block(&mut self, ident: &str, ip: &str) -> Result<bool> {
        trace!("DB: {} blocks {}", ident, ip);
        Ok(self.client.execute("UPDATE clients SET blocks = COALESCE(blocks, '') || $1 || ',' WHERE identifier = $2;", &[&ip, &ident]).await? > 0)
    }

    pub async fn check_block(&self, ident: &str, blocked_ip: &str) -> Result<bool> {
        trace!("DB: {} checks if {} is blocked", ident, blocked_ip);
        let row_ident = self.client.query_one("SELECT blocks FROM clients WHERE identifier = $1;", &[&ident]).await?;
        let blocks: &str = row_ident.try_get(0).unwrap_or_default();
        if !blocks.is_empty() {
            for block in blocks.split(',') {
                if block == blocked_ip {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub async fn is_ident_exists(&self, ident: &str) -> Result<bool> {
        let ident = self.client.query_opt("SELECT identifier FROM clients WHERE identifier = $1", &[&ident]).await?;
        if ident.is_none() {
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
