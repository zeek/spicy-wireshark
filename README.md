Spicy Wireshark Plugin
======================

This is a Wireshark plugin for writing new dissectors with
[Spicy](https://docs.zeek.org/projects/spicy), a high-level language
for parsing arbitrary protocols. By using Spicy, you can add
new dissectors to Wireshark without needing to write C or Lua code.

The plugin should support the standard Unix-style platforms, but not
Windows. 

Installation
------------

You need to build the plugin from source as an external plugin that
Wireshark will load at startup. The plugin links against the Spicy
runtime library, and it requires the Spicy toolchain to compile custom
dissectors.

To build, you need the following prerequisites in place:

- Wireshark version ≥ 4.4, including developer headers
- Spicy version ≥ 1.14 (in development, so you need the
  [main branch from git](https://github.com/zeek/spicy/tree/main) for
  now)
- A reasonable modern version of GCC or Clang with C++20 support
- CMake ≥ 3.15

Make sure that both the Spicy compiler `spicyc` and Wireshark's
`tshark` are in your `PATH`. Then configure and build the plugin:

```
# ./configure && make && make install
```

This will install the plugin into Wireshark's system-wide plugin
directory. If you now run `tshark -G plugins`, you should see the
Spicy plugin listed in the output now.

Optional build customizations:

- If `configure` cannot find the Wireshark installation, you can pass
  it some hints:

  ```
    --wireshark-root=PATH               Override Wireshark root directory
    --wireshark-include-dir=PATH        Override Wireshark include directory
  ```

- To install the plugin into the user's personal plugin directory,
  instead of system-wide, add `--wireshark-use-personal-plugin-dir`
  to the `configure` command.

Instead of installing, you can also just point Wireshark directly to
the plugin's build directory by setting `WIRESHARK_PLUGIN_DIR`:

```
# export WIRESHARK_PLUGIN_DIR=$(pwd)/build/plugin
```

Overview
--------

Basic usage is simple: Write a Spicy grammar that describes the
protocol, compile that grammar with the Spicy compiler into a loadable
module, and then have the plugin load that module into Wireshark at
startup. Generally, any Spicy grammar will work, meaning in particular
you can reuse any existing grammars, such as any [that Zeek
uses](https://docs.zeek.org/en/master/devel/spicy/index.html). 

The only additional piece you need is a small addition to each Spicy
grammar that registers a new dissector with Wireshark, including when
to use it by defining its well-known ports. We walk through that in
more detail in the following example.

Example
-------

We'll create a trivial [UDP
echo](https://datatracker.ietf.org/doc/html/rfc862) dissector for
Wireshark using Spicy. Here's a Spicy grammar that just parses the
content of whole packets into a single, binary `message` field for
both requests and replies:

```spicy
# File: echo.spicy

module Echo;

import Wireshark;

public type Request = unit { 
    message: bytes &eod; # read all payload until end of data
};

public type Reply = unit { 
    message: bytes &eod;
};

# Let Wireshark know about the dissector.
Wireshark::register_dissector([
    $name = "ECHO Protocol",         # long, descriptive dissector name in Wireshark
    $short_name = "spicy_echo",      # shorthand name for the dissector
    $mode = Wireshark::Mode::Packet, # dissect packets individually (common for UDP protocols)
    $ports = set(7/udp),             # well-known port to recognize the protocol
    $parser_orig = Echo::Request,    # type acting as entry point for client-side packets
    $parser_resp = Echo::Reply       # type acting as entry point for server-side packets
]);
```

While the first part is just a standard Spicy grammar, the
`register_dissector()` call at the end tells Wireshark about our new
dissector. We name it `spicy_echo` because Wireshark already has a
built-in `echo` dissector, and short names must be
unique.[^spicy-prefix]

[^spicy-prefix]: Indeed, the plugin automatically prefixes names with
`spicy_` when it finds such a conflict.

We can now compile this Spicy module with:

```
# spicyc -j -L lib/ -Q -o echo.hlto echo.spicy
```

Here, `-j` tells `spicyc` to produce a binary module ready for loading
into Wireshark at runtime. `-L lib/` specifies the directory where the
plugin's `wireshark.spicy` file is located, which is required for the
`import` statement. `-Q` activates offset tracking, which will enable
Wireshark to pinpoint the exact location of parsed fields inside the
packet.

The compilation generates a binary module `echo.hlto`, which is the
compiled dissector that Wireshark can load. For Wireshark to find
this at startup, there are two options:

- You can copy the file into a `spicy/` subdirectory inside
  either Wireshark's global or personal plugin directories. The plugin will
  search there for any `*.hlto` files to load as Spicy modules.

- You can set the environment variable
  `WIRESHARK_SPICY_MODULE_PATH` to point to the directory where the
  `*.hlto` file is located. The plugin will search that directory for
  any Spicy modules to load as well.

We'll do the second here:

```
# export WIRESHARK_SPICY_MODULE_PATH=$(pwd)
```

Now `tshark -G dissectors` should show the new `spicy_echo` dissector:

```
...
spdy	SPDY
spice	Spice
spicy_echo	spicy_echo
spnego	SPNEGO
spnego-krb5	SPNEGO-KRB5
...
```

That means we can now use the new dissector in Wireshark and `tshark`,
using an example `echo` packet trace in the `tests/Traces/` directory:

![Spicy Echo dissector in Wireshark](echo.png)]

We have added a new dissector to Wireshark.


Customizing the Display
-----------------------

Generally, the Spicy plugin derives the shown tree structure from the
Spicy grammar's unit types. Currently there's only one part of this
process that can be customized: the single-line summary string
representing a unit in Wireshark's packet description. By default,
that summary is Spicy's `print` output for the unit (that's the
`[$message=b"Hello, Spicy World!"` in the Echo dissector). However, if
there's an [on
%print()](https://docs.zeek.org/projects/spicy/en/latest/programming/parsing.html#unit-hooks)
hook defined, its output will be used instead.


Display Filters
---------------

For use in display filters, the plugin registers all unit fields with
Wireshark that are reachable from the protocol's entry points. The
field names are generally of the form
`<short_name>.<unit_name>.<field_name>`. For example, in the Echo
dissector, the request's `message` field is accessible as
`spicy_echo.request.message`, and the reply's as
`spicy_echo.reply.message`. 


Dissecting TCP Protocols
------------------------

Dissecting TCP-based protocols is a little bit more involved, as they
typically consist of a series of PDUs split across multiple TCP
segments. To support that, the plugin deploys a slightly different
model, as follows. 

For a TCP protocol, when registering a dissector, set the mode to
`Wireshark::Mode::Stream` instead of `Wireshark::Mode::Packet`. This
tells the plugin that the payload of each side of a connection should
be parsed as single stream of bytes, working with Wireshark's TCP
stream reassembly to reconstruct PDUs from packet as it processes
them.

In stream mode, only a single instance of the entry point unit is used
for parsing the *entire stream* in that direction (whereas, in
contrast, packet mode uses a separate instance for each *packet*). As
most protocols consist of a series of similar PDUs, this usually
require a top-level unit that wraps the sequence of PDUs in a vector.
This top-level unit is then used as the entry point for the dissector.

For illustration, let's look at a simple example for HTTP:

```spicy

module HTTP;

# Entry point for entire stream of all client-side requests.
public type Requests = unit {
    requests:  Request[];
};

# A single HTTP request (i.e., one PDU).
type Request = unit {
    request: RequestLine;           # "GET /index.html HTTP/1.0"
    message: Message(False, True);  # body of the request
};

…

Wireshark::register_dissector([
            …
            $mode = Wireshark::Mode::Stream,
            $parser_orig = HTTP::Requests,
            …
]);
```

One would then add a corresponding `HTTP::Replies` for the server-side
PDUs as well.[^vector-wrapping]

[^vector-wrapping]: Wrapping a PDU type into a top-level vector is a
common pattern in Spicy grammars, independent of Wireshark. Typically,
one would also leave out the field name (`requests` in the example)
to facilitate some code optimizations.

This solves the parsing: the new dissector will now successively parse
each HTTP request as it sees it. But there's still a catch: By
default, Wireshark would only display the parsed data at the *end* of
the stream, because technically that's when the top-level unit has
been fully parsed.[^end-of-stream] For a protocol like HTTP, that's
not really helpful, as we clearly want to see the individual requests
as they arrive. 

[^end-of-stream]: This may be: never! Wireshark doesn't reliably flag
the end of a TCP stream to a dissector; and if the plugin doesn't
learn about the end of the stream, it will not show any dissected data
at all by default. So if your TCP-based dissector doesn't seem to show
any dissected data at all, keep reading for how to provide display
hints.

To address this, a dissector needs to provide a little more help: it
needs to tell the Spicy plugin when a PDU is complete and ready for
display. It can do so by implementing a [Spicy
hook](https://docs.zeek.org/projects/spicy/en/latest/programming/parsing.html#unit-hooks)
that calls the plugin-provided function `Wireshark::display(<unit>)`
at the appropriate time, passing it the unit representing the PDU. In
the HTTP example, that would look like this:

```spicy
on HTTP::Request() {
    Wireshark::display(self); # tell Wireshark to that the request is ready to display
}
```

Note how this decouples the entry point for parsing the TCP stream
(`HTTP::Requests`) from the unit that we'll see associated with
individual packets in Wireshark's output. 

Limitations
-----------

This Wireshark plugin is still very much a work in progress. The main
goal right now is to evaluate the overall feasibility of the approach,
as well as understand what it will take to make it a viable
alternative to writing production dissectors in C or Lua. 

The plugin comes with some limitations for now:

- It currently only supports TCP and UDP protocols. This is not a
  conceptual limitation, the plugin is just lacking ways to register
  other types of dissectors with Wireshark.

- Per above, there are currently only limited options to customize how
  Wireshark displays the parsed data. Whereas a traditional C or Lua
  dissector has full control over the tree structure, the Spicy plugin
  derives the display generically from the protocol's structure. We
  plan to make additional mechanisms available here.

- There's currently no way to provide textual descriptions for any of
  the dissected information. We plan to support documentation strings
  in Spicy code that the plugin will channel through to Wireshark.

- The plugin does not yet support Spicy's unit contexts.

- `tshark` output using `-O <format>` isn't yet supported. While it
  produces output, some of it isn't correct.

Feedback
--------

Feel free to open issues (or pull requests) for anything you'd like to
see different. 

License
-------

This Spicy plugin for Wireshark is open source and released under a BSD
license, which allows for pretty much unrestricted use as long as you
leave the license header in place. 

Footnotes
---------
