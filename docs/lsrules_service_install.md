## lsrules service install

Write the LaunchAgent plist and load it

### Synopsis

Write ~/Library/LaunchAgents/com.schretzi.lsrules.plist and load it.

Idempotent: an already-loaded job is unloaded and reloaded, so this is also
how you apply a change to the plist.

```
lsrules service install [flags]
```

### Options

```
  -h, --help   help for install
```

### Options inherited from parent commands

```
      --binary string   path to the lsrules executable to run (default: the running one)
      --config string   path to config file (default "~/.config/lsrules/config.yaml")
```

### SEE ALSO

* [lsrules service](lsrules_service.md)	 - Manage the lsrules LaunchAgent

