use std::{io, mem::MaybeUninit};

use crate::{io_source::IoSource, event};

/// A structure representing a socket server.
#[derive(Debug)]
pub struct RawSocket {
    inner: IoSource<socket2::Socket>,
}

impl RawSocket {
    /// Creates a new `RawSocket` bound to the specified address.
    pub fn new(protocol:Option<socket2::Protocol>) -> io::Result<RawSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            protocol
        )?;
        socket.set_nonblocking(true)?;
        Ok(RawSocket {
            inner: IoSource::new(socket),
        })
    }

    /// Returns the local address that this socket is bound to.
    pub fn bind(&self, ip: &std::net::Ipv4Addr) -> io::Result<()> {
        let addr = socket2::SockAddr::from(std::net::SocketAddrV4::new(*ip, 0));
        self.inner.bind(&addr)?;
        Ok(())
    }

    /// send data from the socket.
    pub fn send_to(&self, buf: &[u8], ip: &std::net::Ipv4Addr) -> io::Result<usize> {
        let addr = socket2::SockAddr::from(std::net::SocketAddrV4::new(*ip, 0));
        self.inner.do_io(|socket| socket.send_to(buf, &addr)) 
    }

    /// receive data from the socket.
    pub fn recv_from(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, socket2::SockAddr)> {
        self.inner.do_io(|socket| socket.recv_from(buf))
    }
}

impl event::Source for RawSocket {
    fn register(
        &mut self,
        registry: &crate::Registry,
        token: crate::Token,
        interests: crate::Interest,
    ) -> io::Result<()> {
        self.inner.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &crate::Registry,
        token: crate::Token,
        interests: crate::Interest,
    ) -> io::Result<()> {
        self.inner.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &crate::Registry) -> io::Result<()> {
        self.inner.deregister(registry)
    }
}
