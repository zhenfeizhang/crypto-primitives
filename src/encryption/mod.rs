//! This module implements ECIES encryption algorithm as per section 10.2
//! of ISO/IEC 18033-2 <https://www.shoup.net/iso/std4.pdf>.
//! Some of the significant differences are
//!  * The key derivation function (KDF) is build from a non-standard hash
