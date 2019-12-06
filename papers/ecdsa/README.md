# ECDSA Nonce Leakage

This directory contains scripts for re-running nonce leakage analysis
as done in the paper:

Samuel Weiser, David Schrammel, Lukas Bodner, and Raphael Spreitzer.
**Big Numbers -- Big Troubles: Systematically Analyzing Nonce Leakage
in (EC)DSA Implementations**. Usenix Security 2020.

# Dependencies

We have tested DATA using a 64-bit Ubuntu 19.04 and Python 3.7, but it
should also run with other Ubuntu and Debian versions. See
[USAGE.md](../../USAGE.md) for installation instructions.

# Inspect leakage reports

We provide the leakage reports of all benchmarks listed in Table 6 in
the paper, with descriptions of the discovered leakage. You can
download the report archive
[here](https://seafile.iaik.tugraz.at/f/f5487360ff/?raw=1). To view a
report, execute

* `run-gui.sh`

DATA GUI will ask for a result `pickle` file and the corresponding
`framework.zip` file. You can find them in the archive, e.g. under
`openssl/x86_64/dsa_nonce/256`.

# Analyze all

To build and run all benchmarks listed in Table 6 in the paper on your
own, execute `./run-analysis.sh`. Note that this takes several GB of
RAM as well as storage. Furthermore, a system with many CPU cores is
advantageous to speedup parallel analysis.

To speedup the benchmarks, read the comments in `run-analysis.sh`.

The following performance numbers were created on an i5-6200U with 12GB
RAM and Ubuntu 16.04.

|     Configuration                             | sec    | CPU sec |
|-----------------------------------------------|--------|---------|
| BoringSSL ec_nonce P-521                      | 170.67 |  515.08 |
| OpenSSL dsa_nonce 256                         | 424.16 | 1343.56 |
| OpenSSL ec_nonce secp521r1 (nistp_64_gcc_128) | 286.98 |  869.74 |
| OpenSSL ec_nonce secp521r1 (artificial)       | 261.01 |  737.78 |

LibreSSL is currently disabled in `run-analysis.sh`, since this requires
a multicore cluster with enough RAM to finish within reasonable time.
