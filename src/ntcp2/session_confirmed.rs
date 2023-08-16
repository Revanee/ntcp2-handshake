/// +----+----+----+----+----+----+----+----+
/// | router_ident                          |
/// +                                       +
/// |                                       |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// | published                             |
/// +----+----+----+----+----+----+----+----+
/// |size| RouterAddress 0                  |
/// +----+                                  +
/// |                                       |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// | RouterAddress 1                       |
/// +                                       +
/// |                                       |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// | RouterAddress ($size-1)               |
/// +                                       +
/// |                                       |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+-//-+----+----+----+
/// |psiz| options                          |
/// +----+----+----+----+-//-+----+----+----+
/// | signature                             |
/// +                                       +
/// |                                       |
/// +                                       +
/// |                                       |
/// +                                       +
/// |                                       |
/// +                                       +
/// |                                       |
/// +----+----+----+----+----+----+----+----+
///
/// router_ident :: RouterIdentity
///                 length -> >= 387+ bytes
///
/// published :: Date
///              length -> 8 bytes
///
/// size :: Integer
///         length -> 1 byte
///         The number of RouterAddresses to follow, 0-255
///
/// addresses :: [RouterAddress]
///              length -> varies
///
/// peer_size :: Integer
///              length -> 1 byte
///              The number of peer Hashes to follow, 0-255, unused, always zero
///              value -> 0
///
/// options :: Mapping
///
/// signature :: Signature
///              length -> 40 bytes or as specified in router_ident's key
///                        certificate
pub struct RouterInfo {}

/// +----+----+----+----+----+----+----+----+
/// | public_key                            |
/// +                                       +
/// |                                       |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// | padding (optional)                    |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// | signing_key                           |
/// +                                       +
/// |                                       |
/// ~                                       ~
/// ~                                       ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// | certificate                           |
/// +----+----+----+-//
///
/// public_key :: PublicKey (partial or full)
///               length -> 256 bytes or as specified in key certificate
///
/// padding :: random data
///            length -> 0 bytes or as specified in key certificate
///            padding length + signing_key length == 128 bytes
///
/// signing__key :: SigningPublicKey (partial or full)
///                 length -> 128 bytes or as specified in key certificate
///                 padding length + signing_key length == 128 bytes
///
/// certificate :: Certificate
///                length -> >= 3 bytes
///
/// total length: 387+ bytes
pub struct RouterIdentity {}

/// +----+----+----+----+----+-//
/// |type| length  | payload
/// +----+----+----+----+----+-//
///
/// type :: Integer
///         length -> 1 byte
///
///         case 0 -> NULL
///         case 1 -> HASHCASH
///         case 2 -> HIDDEN
///         case 3 -> SIGNED
///         case 4 -> MULTIPLE
///         case 5 -> KEY
///
/// length :: Integer
///           length -> 2 bytes
///
/// payload :: data
///            length -> $length bytes
pub struct Certificate {}
