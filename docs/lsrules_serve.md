## lsrules serve

Run the HTTPS server in the foreground

### Synopsis

Run the HTTPS server in the foreground.

This is what the launchd job executes; run it by hand to see the server's
output on the terminal. It logs every request, so a subscription refresh is
visible as a conditional request answered with 304.

```
lsrules serve [flags]
```

### Options

```
  -h, --help   help for serve
```

### Options inherited from parent commands

```
      --config string   path to config file (default "~/.config/lsrules/config.yaml")
```

### SEE ALSO

* [lsrules](lsrules.md)	 - Serve Little Snitch rule groups over HTTPS from this machine

