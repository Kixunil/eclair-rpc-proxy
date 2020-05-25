Eclair RPC proxy
=================

Finer-grained permission management for eclair.

About
-----

This is a proxy made specifically for `eclair` to allow finer-grained control of permissions. It enables you to specify several users and for each user the list of RPC calls he's allowed to make.

This is useful because `eclair` allows every application with password to make possibly harmful calls like spending all your money. If you have several applications, you can provide the less trusted ones a different password and permissions than the others using this project. Especially, you can allow certain applications, like BTCPayServer to create invoices, but not spend the money.

This is a fork/adaptation of [`btc-rpc-proxy`](https://github.com/Kixunil/btc-rpc-proxy), to support eclair, which works a bit differently.
It's also an explanation for "why not a PR against Eclair instead?". Modifying `btc-rpc-proxy` was very easy and I'm not fluent in Scala.

Usage
-----

For security and performance reasons this application is written in Rust. Thus, you need a recent Rust compiler to compile it.

You need to configure the proxy using config files. You can specify them using `--conf` parameter, or `--conf_dir` to include whole directory (a file per user is a nice way to make configuration clean :)) **Make sure to set their permissions to `600` before you write the passwords to them!**

An example configuration file is provided in this repository, hopefuly it's understandable. After configuring, you only need to run the compiled binary (e.g. using `cargo run --release`)

`--help` option is provided and a man page can be generated using [`cfg_me`](https://github.com/Kixunil/cfg_me).

Limitations
-----------

**BIG FAT WARNING: this project is very young and hasn't been reviewed yet! Use at your own risk! The author reserves the right to publicly ridicule anyone stupid enough to blindly run this!**

Aside the project being young, there are some other issues:

* Various clients don't support changing user names. E.g. BTCPayServer sends empty value, which Toml doesn't support. This is hacked by mapping it to `!!!EMPTY!!!`
* Websocket probably doesn't work. Not tested properly. BTCPayServer works, feel free to report issues with other apps.
* Cookie files not supported by `eclair` and thus not by this proxy either. [Race condition attacks](https://github.com/Kixunil/security_writings/blob/master/cookie_files.md) may be possible.
* Logging can't be configured yet.
* No support for changing UID.
* No support for Unix sockets.
* The quality of the code shouldn't be too bad, but I wouldn't call it "high".

License
-------

MITNFA
