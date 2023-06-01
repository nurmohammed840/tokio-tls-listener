#![doc = include_str!("../README.md")]

pub use rustls_pemfile;
pub use tokio_rustls;
pub use tokio_rustls::rustls;

use std::{
    future::Future,
    io::{BufRead, Result},
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::{rustls::ServerConfig, server::TlsStream};

pub struct TlsListener {
    pub tcp_listener: TcpListener,
    pub tls_acceptor: TlsAcceptor,
}

impl<TlsConf> From<(TcpListener, TlsConf)> for TlsListener
where
    TlsConf: Into<Arc<ServerConfig>>,
{
    #[inline]
    fn from((tcp_listener, conf): (TcpListener, TlsConf)) -> Self {
        Self {
            tcp_listener,
            tls_acceptor: TlsAcceptor::from(conf.into()),
        }
    }
}

impl TlsListener {
    #[inline]
    pub async fn bind(
        addr: impl ToSocketAddrs,
        conf: impl Into<Arc<ServerConfig>>,
    ) -> Result<Self> {
        Ok(TlsListener::from((TcpListener::bind(addr).await?, conf)))
    }

    #[inline]
    pub fn accept_tls(
        &self,
    ) -> impl Future<Output = Result<(TlsStream<TcpStream>, SocketAddr)>> + '_ {
        self.accept_tls_with(|_| {})
    }

    #[inline]
    pub async fn accept_tls_with<F>(&self, f: F) -> Result<(TlsStream<TcpStream>, SocketAddr)>
    where
        F: FnOnce(&mut rustls::ServerConnection),
    {
        let (stream, addr) = self.tcp_listener.accept().await?;
        let tls_stream = self.tls_acceptor.accept_with(stream, f).await?;
        Ok((tls_stream, addr))
    }

    #[inline]
    pub fn into_std(self) -> Result<std::net::TcpListener> {
        self.tcp_listener.into_std()
    }
}

impl std::ops::Deref for TlsListener {
    type Target = TcpListener;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.tcp_listener
    }
}

pub fn tls_config(
    certs: &mut dyn BufRead,
    key: &mut dyn BufRead,
) -> std::result::Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert_chain = load::certs(certs)?;
    let key_der = load::key(key)?.ok_or("no private key found")?;

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;

    Ok(config)
}

pub mod load {
    use super::*;
    use rustls_pemfile::Item;
    use tokio_rustls::rustls::{Certificate, PrivateKey};

    #[inline]
    pub fn certs(rd: &mut dyn BufRead) -> Result<Vec<Certificate>> {
        rustls_pemfile::certs(rd).map(|certs| certs.into_iter().map(Certificate).collect())
    }

    #[inline]
    pub fn key(rd: &mut dyn BufRead) -> Result<Option<PrivateKey>> {
        Ok(match rustls_pemfile::read_one(rd)? {
            Some(Item::PKCS8Key(key) | Item::RSAKey(key)) => Some(PrivateKey(key)),
            _ => None,
        })
    }
}
