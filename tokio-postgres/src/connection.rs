use crate::codec::{BackendMessage, BackendMessages, FrontendMessage, PostgresCodec};
use crate::copy_in::CopyInReceiver;
use crate::error::DbError;
use crate::maybe_tls_stream::MaybeTlsStream;
use crate::observe::{self, RequestObservation};
use crate::{AsyncMessage, Error, Notification};
use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use futures_channel::mpsc;
use futures_util::{ready, stream::FusedStream, Sink, Stream, StreamExt};
use log::{info, trace};
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

pub enum RequestMessages {
    Single(FrontendMessage),
    CopyIn(CopyInReceiver),
}

pub struct Request {
    pub messages: RequestMessages,
    pub sender: mpsc::Sender<BackendMessages>,
    /// Wire accounting for the issuing context; `None` while observation is
    /// off. Dropping it before `ReadyForQuery` counts the cycle as abandoned.
    pub observation: Option<RequestObservation>,
}

pub struct Response {
    sender: mpsc::Sender<BackendMessages>,
    observation: Option<RequestObservation>,
}

#[derive(PartialEq, Debug)]
enum State {
    Active,
    Terminating,
    Closing,
}

/// A connection to a PostgreSQL database.
///
/// This is one half of what is returned when a new connection is established. It performs the actual IO with the
/// server, and should generally be spawned off onto an executor to run in the background.
///
/// `Connection` implements `Future`, and only resolves when the connection is closed, either because a fatal error has
/// occurred, or because its associated `Client` has dropped and all outstanding work has completed.
#[must_use = "futures do nothing unless polled"]
pub struct Connection<S, T> {
    stream: Framed<MaybeTlsStream<S, T>, PostgresCodec>,
    parameters: HashMap<String, String>,
    receiver: mpsc::UnboundedReceiver<Request>,
    pending_request: Option<RequestMessages>,
    pending_responses: VecDeque<BackendMessage>,
    responses: VecDeque<Response>,
    state: State,
    /// Transaction status from the last `ReadyForQuery` (`I`, `T` or `E`).
    transaction_status: u8,
}

impl<S, T> Connection<S, T> {
    /// The TLS session, when the connection uses TLS. With the verifying
    /// rustls connector this exposes the credential generation the session
    /// authenticated with.
    pub fn tls_stream(&self) -> Option<&T> {
        match self.stream.get_ref() {
            MaybeTlsStream::Tls(stream) => Some(stream),
            MaybeTlsStream::Raw(_) => None,
        }
    }
}

impl<S, T> Connection<S, T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(
        stream: Framed<MaybeTlsStream<S, T>, PostgresCodec>,
        pending_responses: VecDeque<BackendMessage>,
        parameters: HashMap<String, String>,
        receiver: mpsc::UnboundedReceiver<Request>,
    ) -> Connection<S, T> {
        Connection {
            stream,
            parameters,
            receiver,
            pending_request: None,
            pending_responses,
            responses: VecDeque::new(),
            state: State::Active,
            transaction_status: b'I',
        }
    }

    fn poll_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<BackendMessage, Error>>> {
        if let Some(message) = self.pending_responses.pop_front() {
            trace!("retrying pending response");
            return Poll::Ready(Some(Ok(message)));
        }

        Pin::new(&mut self.stream)
            .poll_next(cx)
            .map(|o| o.map(|r| r.map_err(Error::io)))
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Result<Option<AsyncMessage>, Error> {
        if self.state != State::Active {
            trace!("poll_read: done");
            return Ok(None);
        }

        loop {
            let message = match self.poll_response(cx)? {
                Poll::Ready(Some(message)) => message,
                Poll::Ready(None) => return Err(Error::closed()),
                Poll::Pending => {
                    trace!("poll_read: waiting on response");
                    return Ok(None);
                }
            };

            let (mut messages, request_complete) = match message {
                BackendMessage::Async(Message::NoticeResponse(body)) => {
                    let error = DbError::parse(&mut body.fields()).map_err(Error::parse)?;
                    return Ok(Some(AsyncMessage::Notice(error)));
                }
                BackendMessage::Async(Message::NotificationResponse(body)) => {
                    let notification = Notification {
                        process_id: body.process_id(),
                        channel: body.channel().map_err(Error::parse)?.to_string(),
                        payload: body.message().map_err(Error::parse)?.to_string(),
                    };
                    return Ok(Some(AsyncMessage::Notification(notification)));
                }
                BackendMessage::Async(Message::ParameterStatus(body)) => {
                    self.parameters.insert(
                        body.name().map_err(Error::parse)?.to_string(),
                        body.value().map_err(Error::parse)?.to_string(),
                    );
                    continue;
                }
                BackendMessage::Async(_) => unreachable!(),
                BackendMessage::Normal {
                    messages,
                    request_complete,
                } => (messages, request_complete),
            };

            let mut response = match self.responses.pop_front() {
                Some(response) => response,
                None => match messages.next().map_err(Error::parse)? {
                    Some(Message::ErrorResponse(error)) => return Err(Error::db(error)),
                    _ => return Err(Error::unexpected_message()),
                },
            };

            match response.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    self.observe_response(&mut response, &messages, request_complete);
                    let _ = response.sender.start_send(messages);
                    if !request_complete {
                        self.responses.push_front(response);
                    }
                }
                Poll::Ready(Err(_)) => {
                    // The issuer stopped listening (for example its future was
                    // dropped), but the exchange still happened on its behalf.
                    self.observe_response(&mut response, &messages, request_complete);
                    // we need to keep paging through the rest of the messages even if the receiver's hung up
                    if !request_complete {
                        self.responses.push_front(response);
                    }
                }
                Poll::Pending => {
                    self.responses.push_front(response);
                    self.pending_responses.push_back(BackendMessage::Normal {
                        messages,
                        request_complete,
                    });
                    trace!("poll_read: waiting on sender");
                    return Ok(None);
                }
            }
        }
    }

    fn poll_request(&mut self, cx: &mut Context<'_>) -> Poll<Option<RequestMessages>> {
        if let Some(messages) = self.pending_request.take() {
            trace!("retrying pending request");
            return Poll::Ready(Some(messages));
        }

        if self.receiver.is_terminated() {
            return Poll::Ready(None);
        }

        match self.receiver.poll_next_unpin(cx) {
            Poll::Ready(Some(request)) => {
                trace!("polled new request");
                self.responses.push_back(Response {
                    sender: request.sender,
                    observation: request.observation,
                });
                Poll::Ready(Some(request.messages))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        loop {
            if self.state == State::Closing {
                trace!("poll_write: done");
                return Ok(false);
            }

            if Pin::new(&mut self.stream)
                .poll_ready(cx)
                .map_err(Error::io)?
                .is_pending()
            {
                trace!("poll_write: waiting on socket");
                return Ok(false);
            }

            let request = match self.poll_request(cx) {
                Poll::Ready(Some(request)) => request,
                Poll::Ready(None) if self.responses.is_empty() && self.state == State::Active => {
                    trace!("poll_write: at eof, terminating");
                    self.state = State::Terminating;
                    let mut request = BytesMut::new();
                    frontend::terminate(&mut request);
                    RequestMessages::Single(FrontendMessage::Raw(request.freeze()))
                }
                Poll::Ready(None) => {
                    trace!(
                        "poll_write: at eof, pending responses {}",
                        self.responses.len()
                    );
                    return Ok(true);
                }
                Poll::Pending => {
                    trace!("poll_write: waiting on request");
                    return Ok(true);
                }
            };

            match request {
                RequestMessages::Single(request) => {
                    let before = self.observe_before_write();
                    let raw = self.observed_raw(&request);
                    Pin::new(&mut self.stream)
                        .start_send(request)
                        .map_err(Error::io)?;
                    self.observe_written(before, raw.as_deref());
                    if self.state == State::Terminating {
                        trace!("poll_write: sent eof, closing");
                        self.state = State::Closing;
                    }
                }
                RequestMessages::CopyIn(mut receiver) => {
                    let message = match receiver.poll_next_unpin(cx) {
                        Poll::Ready(Some(message)) => message,
                        Poll::Ready(None) => {
                            trace!("poll_write: finished copy_in request");
                            continue;
                        }
                        Poll::Pending => {
                            trace!("poll_write: waiting on copy_in stream");
                            self.pending_request = Some(RequestMessages::CopyIn(receiver));
                            return Ok(true);
                        }
                    };
                    let before = self.observe_before_write();
                    let raw = self.observed_raw(&message);
                    Pin::new(&mut self.stream)
                        .start_send(message)
                        .map_err(Error::io)?;
                    self.observe_written(before, raw.as_deref());
                    self.pending_request = Some(RequestMessages::CopyIn(receiver));
                }
            }
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        match Pin::new(&mut self.stream)
            .poll_flush(cx)
            .map_err(Error::io)?
        {
            Poll::Ready(()) => trace!("poll_flush: flushed"),
            Poll::Pending => trace!("poll_flush: waiting on socket"),
        }
        Ok(())
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.state != State::Closing {
            return Poll::Pending;
        }

        match Pin::new(&mut self.stream)
            .poll_close(cx)
            .map_err(Error::io)?
        {
            Poll::Ready(()) => {
                trace!("poll_shutdown: complete");
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                trace!("poll_shutdown: waiting on socket");
                Poll::Pending
            }
        }
    }

    /// Whether the request being written (the most recently accepted one) is
    /// observed. The internal `Terminate` has no response entry.
    fn writing_observed(&self) -> bool {
        self.state == State::Active
            && self
                .responses
                .back()
                .map_or(false, |response| response.observation.is_some())
    }

    fn observe_before_write(&self) -> Option<usize> {
        if self.writing_observed() {
            Some(self.stream.write_buffer().len())
        } else {
            None
        }
    }

    fn observed_raw(&self, message: &FrontendMessage) -> Option<bytes::Bytes> {
        match message {
            FrontendMessage::Raw(raw) if self.writing_observed() => Some(raw.clone()),
            _ => None,
        }
    }

    fn observe_written(&mut self, before: Option<usize>, raw: Option<&[u8]>) {
        let before = match before {
            Some(before) => before,
            None => return,
        };
        let encoded = self.stream.write_buffer().len().saturating_sub(before);
        if let Some(observation) = self
            .responses
            .back_mut()
            .and_then(|response| response.observation.as_mut())
        {
            observation.frontend(raw, encoded);
        }
    }

    fn observe_response(
        &mut self,
        response: &mut Response,
        messages: &BackendMessages,
        request_complete: bool,
    ) {
        let ready = if request_complete {
            messages.ready_status()
        } else {
            None
        };
        if let Some(observation) = response.observation.as_mut() {
            let scan = observe::scan_backend(messages.as_bytes());
            // A complete batch always ends with ReadyForQuery; a missing or
            // invalid status is recorded as an abandoned cycle.
            let status = if request_complete {
                Some(ready.unwrap_or(0))
            } else {
                None
            };
            observation.backend(scan, status, self.transaction_status);
        }
        if let Some(status) = ready {
            self.transaction_status = status;
        }
    }

    /// Returns the value of a runtime parameter for this connection.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(|s| &**s)
    }

    /// Polls for asynchronous messages from the server.
    ///
    /// The server can send notices as well as notifications asynchronously to the client. Applications that wish to
    /// examine those messages should use this method to drive the connection rather than its `Future` implementation.
    ///
    /// Return values of `None` or `Some(Err(_))` are "terminal"; callers should not invoke this method again after
    /// receiving one of those values.
    pub fn poll_message(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<AsyncMessage, Error>>> {
        let message = self.poll_read(cx)?;
        let want_flush = self.poll_write(cx)?;
        if want_flush {
            self.poll_flush(cx)?;
        }
        match message {
            Some(message) => Poll::Ready(Some(Ok(message))),
            None => match self.poll_shutdown(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(None),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S, T> Future for Connection<S, T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        while let Some(message) = ready!(self.poll_message(cx)?) {
            if let AsyncMessage::Notice(notice) = message {
                // Notice text can quote SQL, parameters or row values; log
                // only its severity and SQLSTATE.
                info!("{} ({})", notice.severity(), notice.code().code());
            }
        }
        Poll::Ready(Ok(()))
    }
}
