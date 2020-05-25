extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate hyper;
extern crate futures;
#[macro_use]
extern crate enum_future;
extern crate tokio_core;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;
#[macro_use]
extern crate configure_me;

include_config!();

use std::path::PathBuf;
use std::collections::{HashSet, HashMap};
use futures::Future;
use hyper::{server::Service, Request, Response};
use hyper::{StatusCode, header::ContentLength, Method, Headers};
use std::rc::Rc;
use slog::Logger;
use std::borrow::Borrow;
use hyper::header::Authorization;
use hyper::header::Basic as BasicAuth;


#[derive(Deserialize)]
pub struct User {
    pub password: String,
    pub allowed_calls: HashSet<String>,
}

pub type Users = HashMap<String, User>;

struct ClientContext<U> {
    users: U,
    auth: Authorization<BasicAuth>,
    logger: Logger,
}

impl<U: Borrow<Users>> ClientContext<U> {
    fn is_method_authorized(&self, method: &str) -> bool {
        let username = match &*self.auth.username {
            "" => "!!!EMPTY!!!",
            username => username,
        };

        if let Some(user) = self.users.borrow().get(username) {
            let request_password = self.auth.password.as_ref().map(AsRef::as_ref).unwrap_or("");
            if request_password != user.password {
                error!(self.logger, "Unauthorized call"; "method" => method, "reason" => "invalid password", "required" => &user.password, "provided" => request_password);
                return false;
            }
            if !user.allowed_calls.contains(method) {
                error!(self.logger, "Unauthorized call"; "method" => method, "reason" => "RPC method not permitted");
                return false;
            }
        } else {
            error!(self.logger, "Unauthorized call"; "method" => method, "reason" => "unknown user");
            return false;
        }
        debug!(self.logger, "Permitted call"; "method" => method);
        true
    }

}

type HttpClient = hyper::Client<hyper::client::HttpConnector>;

enum AuthSource {
    Const { username: Option<String>, password: String },
    CookieFile(PathBuf),
}

impl AuthSource {
    fn from_config(user: Option<String>, password: Option<String>, file: Option<PathBuf>) -> Result<Self, &'static str> {
        match (user, password, file) {
            (username, Some(password), None) => Ok(AuthSource::Const { username, password }),
            (None, None, Some(cookie_file)) => Ok(AuthSource::CookieFile(cookie_file)),
            // It could pull it from eclair.conf, but I don't think it's worth my time.
            // PRs open.
            //(None, None, None) => Err("missing authentication information"),
            //_ => Err("either a password and possibly a username or a cookie file must be specified"),
            _ => Err("missing authentication information"),
        }
    }

    fn load_from_file(path: &PathBuf) -> Result<String, std::io::Error> {
        std::fs::read_to_string(path).map(|mut cookie| { if cookie.ends_with('\n') { cookie.pop(); } cookie })
    }

    fn try_load(&self) -> Result<Authorization<String>, std::io::Error> {
        match self {
            AuthSource::Const { username: Some(username), password } => Ok(format!("{}:{}", username, password)),
            AuthSource::Const { username: None, password } => Ok(password.clone()),
            AuthSource::CookieFile(path) => AuthSource::load_from_file(path),
        }
        .map(|auth| {
            let mut header = "Basic ".to_owned();
            base64::encode_config_buf(&auth, base64::STANDARD, &mut header);
            header
        })
        .map(Authorization)
    }
}

struct Proxy {
    users: HashMap<String, User>,
    auth: AuthSource,
    client: HttpClient,
    dest_uri: hyper::Uri,
}

struct ProxyHandle {
    proxy: Rc<Proxy>,
    logger: Logger,
}

impl ProxyHandle {
    fn new<T: 'static + slog::SendSyncRefUnwindSafeKV>(&self, values: slog::OwnedKV<T>) -> Self {
        ProxyHandle {
            proxy: Rc::clone(&self.proxy),
            logger: self.logger.new(values),
        }
    }
}

impl std::ops::Deref for ProxyHandle {
    type Target = Proxy;

    fn deref(&self) -> &Self::Target {
        &self.proxy
    }
}

impl Service for ProxyHandle {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<dyn Future<Item=Self::Response, Error=Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        fn send_bad_request() -> impl Future<Item=Response, Error=hyper::Error> {
            const BAD_REQUEST: &str = "{ \"error\" : \"bad request\" }";
            futures::future::ok(Response::new()
                .with_status(StatusCode::BadRequest)
                .with_header(ContentLength(BAD_REQUEST.len() as u64))
                .with_body(BAD_REQUEST))
        }

        fn send_unauthorized() -> impl Future<Item=Response, Error=hyper::Error> {
            const UNAUTHORIZED: &str = "{ \"error\" : \"unauthorized\" }";
            futures::future::ok(Response::new()
                .with_status(StatusCode::Unauthorized)
                .with_header(ContentLength(UNAUTHORIZED.len() as u64))
                .with_body(UNAUTHORIZED))
        }

        fn send_internal_error() -> impl Future<Item=Response, Error=hyper::Error> {
            const INTERNAL_ERROR: &str = "{ \"error\" : \"internal server error\" }";
            futures::future::ok(Response::new()
                .with_status(StatusCode::InternalServerError)
                .with_header(ContentLength(INTERNAL_ERROR.len() as u64))
                .with_body(INTERNAL_ERROR))
        }

        fn forward_call(client: &HttpClient, http_method: Method, uri: hyper::Uri, http_version: hyper::HttpVersion, headers: Headers, body: hyper::Chunk) -> impl Future<Item=Response, Error=hyper::Error> {
            let mut request = Request::new(http_method, uri);
            request.set_version(http_version);
            *request.headers_mut() = headers;
            request.set_body(body);

            client.request(request).map(|mut response| {
                let mut forwarded = Response::new();
                forwarded.set_status(response.status());
                std::mem::swap(forwarded.headers_mut(), response.headers_mut());
                forwarded.set_body(response.body());

                forwarded
            })
        }

        let (http_method, uri, http_version, mut headers, body) = req.deconstruct();

        if http_method == Method::Post && uri.path().starts_with("/") {
            if let Some(auth) = headers.remove::<hyper::header::Authorization<hyper::header::Basic>>() {
                use futures::Stream;

                let this = self.new(o!("user" => auth.username.clone()));
                Box::new(body.concat2().and_then(move |body| {
                    enum_future!(Ret, Forward, Unauthorized, InternalError);

                    let ctx = ClientContext {
                        users: &this.users,
                        auth,
                        logger: this.logger.clone(),
                    };

                    if ctx.is_method_authorized(&uri.path()[1..]) {
                        let logger = &this.logger;
                        this
                            .auth
                            .try_load()
                            .map(|auth| {
                                headers.set(auth);
                                let new_uri = format!("{}://{}{}", this.dest_uri.scheme().unwrap_or("http"), this.dest_uri.authority().unwrap_or("localhost"), uri.path()).parse().expect("Invalid URI");

                                Ret::Forward(forward_call(&this.client, http_method, new_uri, http_version, headers, body))
                            })
                            .map_err(|err| {
                                if err.kind() != std::io::ErrorKind::NotFound {
                                    error!(logger, "Failed to read cookie file: {}", err);
                                }

                                send_internal_error()
                            })
                            .unwrap_or_else(Ret::InternalError)
                    } else {
                            Ret::Unauthorized(send_unauthorized())
                    }
                }))
            } else {
                error!(self.logger, "User unauthorized");
                Box::new(send_unauthorized())
            }
        } else {
            error!(self.logger, "Bad request");
            Box::new(send_bad_request())
        }
    }
}

fn main() {
    use futures::Stream;
    use slog::Drain;

    let (config, _) = config::Config::including_optional_config_files(std::iter::empty::<&str>()).unwrap_or_exit();
    let auth = AuthSource::from_config(config.eclair_user, config.eclair_password, None, /* reserved if Eclair ever implements cookie files: config.cookie_file*/)
        .unwrap_or_else(|msg| {
            eprintln!("Configuration error: {}", msg);
            std::process::exit(1);
        });

    let dest_uri = format!("http://{}:{}", config.eclair_address, config.eclair_port).parse().unwrap();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, o!());

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();

    let addr = std::net::SocketAddr::new(config.bind_address, config.bind_port);
    info!(logger, "Binding"; "bind address" => addr);
    let listener = tokio_core::net::TcpListener::bind(&addr, &handle).unwrap();
    let proxy = Proxy {
        auth,
        users: config.user,
        client: HttpClient::new(&handle),
        dest_uri,
    };
    let service = ProxyHandle { proxy: Rc::new(proxy), logger: logger.new(o!()) };

    let incoming = listener
        .incoming()
        .map_err(|err| error!(logger, "Failed to accept connection"; "error" => %err))
        .map(move |(socket, addr)| {
            let service = service.new(o!("client address" => addr));
            info!(service.logger, "Connected client");
            let err_logger = service.logger.new(o!());
            hyper::server::Http::<hyper::Chunk>::new()
                .serve_connection(socket, service)
                .map_err(move |err| error!(err_logger, "Connection encountered an error"; "error" => %err))
        });

    let server = incoming.for_each(move |connection| {
        handle.spawn(connection);
        Ok(())
    });
    core.run(server).unwrap();
}
