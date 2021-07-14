# Multi-party Private Set Union-Cardinality (MPSU-CA)
This library lets `n` parties who each have a set of `k` elements estimate how many disctinct elements they have without
revealing the actual elements. We proposed this protocol in the paper:

**Compare Before You Buy: Privacy-Preserving
Selection of Threat Intelligence Providers**<br>
*Jelle Vos (me), Zekeriya Erkin and Christian Doerr.*

## Building the project
You can build the project if you have `cargo` installed using `cargo build --release`.

## Running the project
After building, you should have a file called `mpsu_ca` which you can execute on a unix machine using `./mpsu_ca`. 

## Acknowledgements
Many thanks to the authors of our dependencies. In particular, the those who developed the excellent `curve25519-dalek`
crate that implements Curve25519 and the Ristretto encoding.
