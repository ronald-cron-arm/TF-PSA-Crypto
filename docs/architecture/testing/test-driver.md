## Goal
For driver-dispatch testing, build test drivers that implement selected parts
of the PSA driver interface. The test drivers are derived from the built-in
implementation.

### Rationale
- When drivers are involved, we must verify the correct dispatch of cryptographic
  operations between drivers and the built-in implementation.
- If TF-PSA-Crypto implements an entry point and we can derive driver entry points
  from it, we can cover most dispatch scenarios without relying on third-party code.

## Requirements
### In-repo driver likeness
A test driver should, as much as possible, look like a normal driver such as the
`builtin` or `p256-m` ones.

#### Rationale
- Encourages better code organization and smoother driver integration.
- Simplifies maintenance: as driver handling and integration evolves, keeping
  built test drivers aligned with in-repo drivers reduces churn.
  
### Config parity
The cryptographic mechanisms supported by a test driver should be configurable
with the same flexibility as the built-in implementation.

#### Rationale
Enables testing of most scenarios where support for specific mechanisms is
delegated to a driver.

### Miscellaneous
Test driver support is only required on Linux platforms.

## A test driver in TF-PSA-Crypto
A test driver in TF-PSA-Crypto is a copy of the built-in driver with most of its
C symbols renamed. Like the built-in driver, a test driver is configured
through `PSA_WANT_` (common to all drivers) and `_ACCEL_` macros (specific to
each driver).

### Blueprint of a driver in TF-PSA-Crypto
- A driver resides in a subdirectory under `drivers/`, which contains its headers
  and source code.
- Each driver directory includes an `include/` subdirectory. Headers from this
  directory are typically included by the core and other drivers (e.g., because
  of key attribute manipulation).
- Each driver directory is added to the CMake build system as a subdirectory and
  contains a `CMakeList.txt` file to build its code.
- Driver entry points share a common prefix, e.g. `mbedtls_`, `p256_`.

### Building a test driver (`libtestdriver1`) from `builtin`
Test drivers are built by a Python script (`build_test_driver.py`). When
building the test driver named `libtestdriver1`, it performs the following
actions:
- Copy the `drivers/builtin` tree to `drivers/libtestdriver1`, excluding C
  modules and headers that are not driver code (e.g `asn1parse.c`, `lms.c`,
  `memory_buffer_alloc.c`, `pk.c`, `platform.c`, `threading.c`).
- Rename `drivers/libtestdriver1/include/mbedtls` to
         `drivers/libtestdriver1/include/libtestdriver1`, so that headers
  from the test driver are included with `#include libtestdriver1/...`.
- Update header inclusions: replace `#include "mbedtls/..."` with
  `#include "libtestdriver1/...` when the corresponding header exists under
  `drivers/libtestdriver1/include/libtestdriver1`.
- In C source and header files, prefix C symbols that start with
  `TF_PSA_CRYPTO_MBEDTLS_`, `TF_PSA_CRYPTO_PSA_CRYPTO_`, `mbedtls_`, `MBEDTLS_`,
  `psa_`, or `PSA_`, except for those declared in TF-PSA-Crypto public headers
  and `core` headers. Use the prefix `LIBTESTDRIVER1_` for the symbols written
  in uppercase, `libtestdriver1_` for lowercase symbols. In practice, `ctags`
  is used to extract the C symbols from the C modules and headers.

### Configuration of builds with test drivers
Configuration is done using a user configuration file specified with the
`TF_PSA_CRYPTO_USER_CONFIG_FILE` CMake option. This user configuration file
defines `_ACCEL_` macros for both the built-in and test drivers, controlling
which cryptographic mechanisms to disable in each driver.

At this stage, only one test driver is supported.  
Its `_ACCEL_` macros are derived (mirrored against the defined `PSA_WANT_` macros)
from those of the built-in driver (see `tests/configs/user-config-test-driver-extension.h`).

### Issues encountered with the current code base when building a test driver
- Non-driver code under `drivers/builtin/`:
  Some non-driver files are located under this directory. These are filtered
  by `build_test_driver.py`.

- Header placement (`crypto_builtin_xyz.h`):
  The headers defining the operation structures of the built-in code were
  previously located under `include/mbedtls/` instead of  
  `drivers/builtin/include/mbedtls/`. These headers have now been moved.

- Duplicate definitions (built-in vs. test driver):
  Some symbols were declared in public headers but implemented in driver modules
  (e.g., `mbedtls_ct_memcmp`, `mbedtls_psa_get_random`). The modules
  `constant_time.c` and `psa_util.c` have been split, with the parts defining
  functions declared in public headers now moved to `core/`.

- Missing symbols in the test driver:
  Some functions were declared in driver headers but defined in non-driver
  modules (e.g., `mbedtls_asn1_get_mpi`, declared in
  `drivers/builtin/include/mbedtls/private/bignum.h`, but implemented in
  `asn1parse.c`). The functions `mbedtls_asn1_get_mpi` and
  `mbedtls_asn1_write_mpi` have been moved to `bignum.c`.
