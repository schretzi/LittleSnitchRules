## lsrules service

Manage the lsrules LaunchAgent

### Synopsis

Manage the launchd job that runs lsrules in the background.

  label   com.schretzi.lsrules
  plist   ~/Library/LaunchAgents/com.schretzi.lsrules.plist
  log     ~/Library/Logs/lsrules.log
  stderr  ~/Library/Logs/lsrules.err.log

Both logs are rotated by newsyslog, configured in MacbookSetup under
etc/newsyslog.d/lsrules.conf.

### Options

```
      --binary string   path to the lsrules executable to run (default: the running one)
  -h, --help            help for service
```

### Options inherited from parent commands

```
      --config string   path to config file (default "~/.config/lsrules/config.yaml")
```

### SEE ALSO

* [lsrules](lsrules.md)	 - Serve Little Snitch rule groups over HTTPS from this machine
* [lsrules service install](lsrules_service_install.md)	 - Write the LaunchAgent plist and load it
* [lsrules service restart](lsrules_service_restart.md)	 - Unload and reload the LaunchAgent
* [lsrules service start](lsrules_service_start.md)	 - Load the LaunchAgent
* [lsrules service status](lsrules_service_status.md)	 - Show whether the LaunchAgent is installed, loaded and running
* [lsrules service stop](lsrules_service_stop.md)	 - Unload the LaunchAgent
* [lsrules service uninstall](lsrules_service_uninstall.md)	 - Unload the LaunchAgent and remove its plist

