## lsrules

Serve Little Snitch rule groups over HTTPS from this machine

### Synopsis

Serve Little Snitch rule groups (.lsrules) over HTTPS from this machine.

Little Snitch subscribes to a rule group by URL and refuses anything but
HTTPS - a local file is rejected with "For security reasons, only HTTPS URLs
are allowed". Publishing the files somewhere public is the other way to
satisfy that, but a rule group describes what runs on this machine, so this
serves them from it instead, on loopback, with a certificate from the
machine's own CA.

### Options

```
      --config string   path to config file (default "~/.config/lsrules/config.yaml")
  -h, --help            help for lsrules
```

### SEE ALSO

* [lsrules config](lsrules_config.md)	 - Create and validate configuration
* [lsrules serve](lsrules_serve.md)	 - Run the HTTPS server in the foreground
* [lsrules service](lsrules_service.md)	 - Manage the lsrules LaunchAgent
* [lsrules status](lsrules_status.md)	 - Show what is served, whether the port answers, and the launchd job
* [lsrules version](lsrules_version.md)	 - Print the lsrules version, build info and licence

