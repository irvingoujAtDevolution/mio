use std::{io, mem::MaybeUninit, time::Duration};

use mio::net::RawSocket;
use std::env;

pub fn main() -> io::Result<()> {
    let mut raw_socket = RawSocket::new(Some(socket2::Protocol::ICMPV4)).unwrap();

    env::set_var("RUST_LOG", "trace");
    env_logger::init();

    let mut poll = mio::Poll::new().unwrap();

    poll.registry()
        .register(
            &mut raw_socket,
            mio::Token(15),
            mio::Interest::READABLE | mio::Interest::WRITABLE,
        )
        .unwrap();

    let echo_request: Vec<u8> = vec![
        8, 0, 77, 1, 0, 1, 0, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    ];

    let local_echo_addr = std::net::Ipv4Addr::new(127, 0, 0, 1);

    raw_socket.send_to(&echo_request, &local_echo_addr).unwrap();
    let mut events = mio::Events::with_capacity(1024);
    loop {
        println!("polling events");
        if let Err(err) = poll.poll(&mut events, Some(Duration::from_millis(1000))) {
            if err.kind() == io::ErrorKind::Interrupted || err.kind() == io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(err);
        }

        // Process each event.
        for event in events.iter() {
            // Validate the token we registered our socket with,
            // in this example it will only ever be one but we
            // make sure it's valid none the less.
            match event.token() {
                token => {
                    println!("token: {:?}", token);
                    let mut buf = [MaybeUninit::uninit(); 1024];
                    let (usize, addr) = match raw_socket.recv_from(&mut buf) {
                        Ok(res) => {
                            raw_socket.send_to(&echo_request, &local_echo_addr).unwrap();
                            res
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                break;
                            } else {
                                panic!("error: {:?}", e);
                            }
                        }
                    };
                    println!(
                        "Received {} bytes from {:?}",
                        usize,
                        addr.as_socket_ipv4().unwrap()
                    );
                }
                _ => {
                    panic!("should never happen");
                }
            }
        }
    }
}
