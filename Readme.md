Hex-Rays IDAPro Go disassembly plugin


#### REQUIREMENTS

We have recently moved compilation to vagrant!

Incidentally, vagrant has also become a requirement to work with this project,
or alternatively an ubuntu version with go1.9

Since we need several go binaries and need to preserve the context of binaries,
binaries are pushed to the github repo. This also means that to build your go
binaries set your $GOPATH to ugo/go

```bash
export GOPATH=$(pwd)/go
```

To use the plugin, simply symlink or copy the contents of the /src directory
to $IDAPATH/plugins/

Currently, test.py and src/ugo are required to run anything that works


Updated


#### DEPRECATED

Most of the command line utilities are
currently created with MacOS in mind, so
these requirements are also for a Mac
development environment.

* coreutils - required for greadlink - pulls full paths of files
* ida64 - this better be on your path somewhere (v6.8 >)
* python(2.7 >) - please
* go(1.9 >) - this is version at dev

https://www.hex-rays.com/products/ida/support/idadoc/417.shtml

Hexrays doesnt understand what go is doing.

- feed hex-rays more information
- type inferencing

- goUtils already does \_\_interface\_\_ replacement

set size of int to 4