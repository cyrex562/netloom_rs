///
/// ## slip.rs
/// 
/// support Serial Line IP protocol
/// ref: IETF RFC1055 
/// 
/// * special characters: END 192, ESC 219.
/// * sending data: host sends data in the packet. 
///   * If a byte is the same code as an END  character, a two byte sequence of ESC and 
///     220 is sent instead.
///   * If a byte is the same as an ESC char a two byte sequence of ESC and 221 is sent 
///     instead.
///   * Begin and end packets with an END char
/// * 1006 bytes recommended maximum datagram size
/// * SLIP does not implicitly provide addressing
/// * 