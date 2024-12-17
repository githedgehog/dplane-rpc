# Dplane-RPC C library

Contains a C library with the implementation of the wire protocol for CP-DP communications.

## Build

```
mkdir build; cd build
cmake [-DCMAKE_BUILD_TYPE=Debug] [-DMAX_ECMP=32] ..
cmake --build .
```

## Install  
From `build` directory:

```
sudo cmake --install . [--prefix PREF]
```

### Run tests

In the build directory:

```
make test
```

### Link
Add `-ldplane-rpc` to the linker flags to link this library.

