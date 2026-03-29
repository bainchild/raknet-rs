use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use futures::Stream;
use log::{debug, trace};
use pin_project_lite::pin_project;

use crate::link::SharedLink;
use crate::packet::connected::{Flags, Fragment, Ordered, FrameBody};
use crate::packet::unconnected;
use crate::utils::timestamp;
use crate::{Peer, Role};

pub(crate) trait HandleOnline: Sized {
    fn handle_online(self, role: Role, peer: Peer, link: SharedLink, passwords: Vec<[u8; 6]>, check_password: bool) -> OnlineHandler<Self>;
}

impl<F> HandleOnline for F
where
    F: Stream<Item = FrameBody>,
{
    fn handle_online(self, role: Role, peer: Peer, link: SharedLink, passwords: Vec<[u8; 6]>, check_password: bool) -> OnlineHandler<Self> {
        OnlineHandler {
            frame: self,
            role,
            peer,
            state: HandshakeState::WaitConnRequest,
            link,
            passwords,
            check_password
        }
    }
}

pin_project! {
    pub(crate) struct OnlineHandler<F> {
        #[pin]
        frame: F,
        role: Role,
        peer: Peer,
        state: HandshakeState,
        link: SharedLink,
        passwords: Vec<[u8; 6]>,
        check_password: bool,
    }
}

#[derive(Debug)]
enum HandshakeState {
    WaitConnRequest,
    WaitNewIncomingConn,
    Connected,
}

impl<F> Stream for OnlineHandler<F>
where
    F: Stream<Item = FrameBody>,
{
    type Item = Bytes;//(Bytes, Option<Flags>, Option<Ordered>, Option<Fragment>);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            match this.state {
                HandshakeState::WaitConnRequest => {
                    let Some(body) = ready!(this.frame.as_mut().poll_next(cx)) else {
                        return Poll::Ready(None);
                    };
                    if let FrameBody::ConnectionRequest {
                        request_timestamp,
                        use_encryption,
                        password,
                        ..
                    } = body
                    {
                        trace!("received password {:X?} ({:?})",password,use_encryption);
                        if *this.check_password && !this.passwords.contains(&password) { // the zero padding on read and zero stripping on write make correct passwords equivalent. (in this impl, trailing zeros aren't allowed)
                            this.link.send_unconnected(unconnected::Packet::InvalidPassword {
                                magic: (),
                                server_guid: this.role.guid()
                            });
                            continue;
                        }
                        if use_encryption {
                            this.link.send_unconnected(
                                unconnected::Packet::ConnectionRequestFailed {
                                    magic: (),
                                    server_guid: this.role.guid(),
                                },
                            );
                            continue;
                        }
                        let system_addr = if this.peer.addr.is_ipv6() {
                            SocketAddr::new(
                                std::net::IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                                0,
                            )
                        } else {
                            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
                        };
                        this.link
                            .send_frame_body(FrameBody::ConnectionRequestAccepted {
                                client_address: this.peer.addr,
                                system_index: 0,
                                system_addresses: [system_addr; 20],
                                request_timestamp,
                                accepted_timestamp: timestamp(),
                            });
                        *this.state = HandshakeState::WaitNewIncomingConn;
                        trace!("new state {:?}",this.state);
                        continue;
                    }
                    debug!("[{}] ignore packet {body:?} on WaitConnRequest", this.role);
                }
                HandshakeState::WaitNewIncomingConn => {
                    let Some(body) = ready!(this.frame.as_mut().poll_next(cx)) else {
                        return Poll::Ready(None);
                    };
                    if let FrameBody::NewIncomingConnection { .. } = body {
                        debug!("[{}] accept new incoming connection", this.role);
                        *this.state = HandshakeState::Connected;
                        continue;
                    }
                    // FIXME: it is wrong, client should finish handshake before sending user data
                    // currently, the client's handshake is lazy, so user data may be sent before
                    match body {
                        FrameBody::User(data) => return Poll::Ready(Some(data)),
                        _ => {
                            debug!(
                                "[{}] ignore packet {body:?} on WaitNewIncomingConn",
                                this.role
                            );
                        }
                    }
                }
                HandshakeState::Connected => {
                    let Some(body) = ready!(this.frame.as_mut().poll_next(cx)) else {
                        return Poll::Ready(None);
                    };
                    match body {
                        FrameBody::ConnectedPing { client_timestamp } => {
                            trace!(
                                "[{}] receive ConnectedPing from {}, send ConnectedPong back",
                                this.role,
                                this.peer
                            );
                            this.link.send_frame_body(FrameBody::ConnectedPong {
                                client_timestamp,
                                server_timestamp: timestamp(),
                            });
                        }
                        FrameBody::User(data) => {
                            // let frame = this.frame.as_ref();
                            return Poll::Ready(Some(data)); //(data,frame.flags.clone(),frame.ordered.clone(),frame.fragment.clone())))
                        },
                        _ => {
                            debug!("[{}] ignore packet {body:?} on Connected", this.role);
                        }
                    }
                }
            }
        }
    }
}
