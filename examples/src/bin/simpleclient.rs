/// This is the simplest possible client using rustls that does something useful:
/// it accepts the default configuration, loads some root certs, and then connects
/// to google.com and issues a basic HTTP request.  The response is printed to stdout.
///
/// It makes use of rustls::Stream to treat the underlying TLS connection as a basic
/// bi-directional stream -- the underlying IO is performed transparently.
///
/// Note that `unwrap()` is used to deal with networking errors; this is not something
/// that is sensible outside of example code.
use std::sync::Arc;

use std::{
    io::{stdout, Read, Write},
    net::TcpStream,
};

use rustls::{AlertDescription, OwnedTrustAnchor, RootCertStore};

pub struct MyError();

impl Into<rustls::error::Error> for MyError {
    fn into(self) -> rustls::error::Error {
        rustls::error::Error::BadMaxFragmentSize
    }
}

/// Tests if the server sends back a BadRecordMac alert
fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    use rustls::tls12;

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&[
            tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Almost none of these domains react to client sending close_notify anymore (as of Jul 13 2023)
    let domains = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "wikipedia.org",
        "yahoo.com",
        "whatsapp.com",
        "amazon.com",
        "live.com",
        "netflix.com",
        "reddit.com",
        "linkedin.com",
        "twitch.com",
        "discord.com",
        "microsoft.com",
        "ebay.com",
        "apple.com",
    ];

    // These domains react with a BadRecordMac alert
    let domains_which_react_to_bad_mac = [
        "reddit.com",
        "apple.com",
        "cnn.com",
        "nytimes.com",
        "pinterest.com",
        "nasa.gov",
        "bbc.com",
        "theguardian.com",
        "usatoday.com",
    ];
    // let domains = domains_which_react_to_bad_mac;

    for domain in domains {
        let server_name = domain.try_into().unwrap();
        let mut conn =
            rustls::ClientConnection::new(Arc::new(config.clone()), server_name).unwrap();
        let mut sock = TcpStream::connect(&format!("{domain}:443")).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(
            &format!("GET / HTTP/1.1\r\nHost: {domain}\r\nAccept-Encoding: identity\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();

        let mut plaintext = vec![0u8; 32];
        _ = tls.read_exact(&mut plaintext);

        println!("{:?}", std::str::from_utf8(&plaintext).unwrap());

        std::thread::sleep(std::time::Duration::from_secs(1));

        // Uncomment either `send_close_notify` or `send_app_data_bad_mac` but NOT BOTH

        tls.conn.send_close_notify();
        //tls.conn.send_app_data_bad_mac();

        tls.flush().unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));

        println!(
            "{} {} {}",
            domain,
            tls.conn
                .current_io_state()
                .peer_sent_bad_record_mac_alert,
            tls.conn
                .current_io_state()
                .peer_has_closed
        );
    }
}
