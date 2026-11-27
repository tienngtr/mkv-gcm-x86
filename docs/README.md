# Public references

## MKV specification

- N. B. Cuong and D. V. Truong, *Encryption algorithms – Block cipher MKV*.
  Internet-Draft `draft-nbcuong-mkv-block-cipher-00`, July 2026, work in
  progress. Appendix A.1.3 gives a test vector for the 128-bit block,
  256-bit key variant used here.
  [Local text](draft-nbcuong-mkv-block-cipher-00.txt) ·
  [IETF archive](https://www.ietf.org/archive/id/draft-nbcuong-mkv-block-cipher-00.html) ·
  [Draft status](https://datatracker.ietf.org/doc/draft-nbcuong-mkv-block-cipher/)
- *TCVN 14263:2024*, Vietnam's national MKV block cipher standard.
  [VSQI catalog](https://tieuchuan.vsqi.gov.vn/tieuchuan/view?sohieu=TCVN+14263%3A2024)

The local draft is the unmodified IETF text. Its own copyright notice and
[IETF Trust terms](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/)
apply to that file. Its SHA-256 is
`0d7690796a43e6c17f54701ca5033273ccacc52ef46457b49b033f1582af1be9`.
The repository's MIT license applies to the project source.

### Appendix A.1.3 discrepancy

For the 256-bit key and plaintext printed in Appendix A.1.3, both this
implementation and libmkvpp produce `b4f6ac1b9fdcb1506cf10f5cf84881a1`.
The draft lists `8a6f9bbc745bfee7005f04054dd1ff8e` for that input.
The cause remains unresolved. The library tests use the reference
implementation's block fixture and independently generated GCM fixtures.

## Design paper

B. C. Nguyen, V. L. Nguyen, T. A. Nguyen, S. N. Tran, D. L. Tran and
D. L. Hoang, *MKV: a new block cipher for the post-quantum cryptography
transition*, Mathematical Aspects of Cryptography, 16(2), 113–138, 2025.
The paper describes the cipher's design and includes implementation
experiments. The publisher provides the full-text PDF on Math-Net.
[Math-Net article and PDF](https://www.mathnet.ru/eng/mvk497) ·
[DOI 10.4213/mvk497](https://doi.org/10.4213/mvk497)

## GCM

M. Dworkin, *Recommendation for Block Cipher Modes of Operation:
Galois/Counter Mode (GCM) and GMAC*, NIST SP 800-38D, 2007.
Sections 6–7 describe GHASH and the authenticated encryption construction.
[NIST publication](https://csrc.nist.gov/pubs/sp/800/38/d/final)
