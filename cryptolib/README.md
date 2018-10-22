# Cryptolib

This directory contains the individual frameworks that are tested with DATA.
To add a new framework to test, copy the `template` directory and adapt
the files accordingly.

## Preloading

DATA supports preloading shared libraries. This is helpful to override
system libraries which are usually stripped of all debug symbols.

### glibc
If you want to analyze leakage in glibc, you can build your own glibc with
debug symbols enabled. This is done via

```
cd common/preload/glibc
./build.sh
```

Note: This might take 2-3 GB of disk space. 

Note: If compilation is finished, you can abort the glibc regression tests and
re-run `./build.sh` which will link the shared library to the `preload` dir.

### Custom libraries

If you want to link other custom libraries, e.g. `foo`, create a separate folder
`common/preload/foo` where all source and binary files are located.
Then, build it and link the shared library to the preload folder, 
e.g. `common/preload/foo.so`.

To verify that DATA indeed used the library, check the file `env.txt` in 
the `results` directory. It will list all custom libraries in the
`LD_PRELOAD` environment variable.
