//! bzip2 decoding APIs

use std::convert::TryInto;

pub use self::error::DecoderError;
pub use self::reader::DecoderReader;
use crate::bitreader::BitReader;
use crate::block::Block;
use crate::header::Header;

mod error;
mod reader;

/// A low-level decoder implementation
///
/// This decoder does no IO by itself, instead enough data
/// has to be written to it in order for it to be able
/// to decode the next block. After that the decompressed content
/// for the block can be read until all of the data from the block
/// has been exhausted.
/// Repeating this process for every block in sequence will result
/// into the entire file being decompressed.
///
/// ```rust
/// use bzip2_rs::decoder::{Decoder, ReadState, WriteState};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut compressed_file: &[u8] = include_bytes!("../../tests/samplefiles/sample1.bz2").as_ref();
/// let mut output = Vec::new();
///
/// let mut decoder = Decoder::new();
///
/// assert!(
///     !compressed_file.is_empty(),
///     "empty files will cause the following loop to spin forever"
/// );
///
/// let mut buf = [0; 1024];
/// loop {
///     match decoder.read(&mut buf)? {
///         ReadState::NeedsWrite(space) => {
///             // `Decoder` needs more data to be written to it before it
///             // can decode the next block.
///             // If we reached the end of the file `compressed_file.len()` will be 0,
///             // signaling to the `Decoder` that the last block is smaller and it can
///             // proceed with reading.
///             match decoder.write(&compressed_file)? {
///                 WriteState::NeedsRead => unreachable!(),
///                 WriteState::Written(written) => compressed_file = &compressed_file[written..],
///             };
///         }
///         ReadState::Read(n) => {
///             // `n` uncompressed bytes have been read into `buf`
///             output.extend_from_slice(&buf[..n]);
///         }
///         ReadState::Eof => {
///             // we reached the end of the file
///             break;
///         }
///     }
/// }
///
/// // `output` contains the decompressed file
/// let decompressed_file: &[u8] = include_bytes!("../../tests/samplefiles/sample1.ref").as_ref();
/// assert_eq!(output, decompressed_file);
/// #
/// # Ok(())
/// # }
/// ```
pub struct Decoder {
    header_block: Option<(Header, Block)>,

    skip_bits: usize,
    in_buf: Vec<u8>,
    /// Bytes at the front of `in_buf` the current block has already consumed.
    ///
    /// VENDORED PATCH. Upstream kept no such cursor: it called
    /// `in_buf.drain(..bytes)` in exactly one place, and that place is
    /// unreachable — `block.is_not_ready()` only becomes true on the call that
    /// returns `read == 0`, which returns early. So the staging buffer was
    /// never drained at all and accumulated the whole compressed stream.
    consumed: usize,

    eof: bool,
}

/// State returned by [`Decoder::write`]
pub enum WriteState {
    /// Enough data has already been written to [`Decoder`]
    /// in order for it to be able to decode the next block.
    /// Now call [`Decoder::read`] to read the decompressed data.
    NeedsRead,
    /// N. number of bytes have been written.
    Written(usize),
}

/// State returned by [`Decoder::read`]
pub enum ReadState {
    /// Not enough data has been written to the underlying [`Decoder`]
    /// in order to allow the next block to be decoded. Call
    /// [`Decoder::write`] to write more data. If the end of the file
    /// has been reached, call [`Decoder::write`] with an empty buffer.
    NeedsWrite(usize),
    /// N. number of data has been read
    Read(usize),
    /// The end of the compressed file has been reached and
    /// there is no more data to read
    Eof,
}

impl Decoder {
    /// Construct a new [`Decoder`], ready to decompress a new bzip2 file
    pub fn new() -> Self {
        Self {
            header_block: None,

            skip_bits: 0,
            in_buf: Vec::new(),
            consumed: 0,

            eof: false,
        }
    }

    /// VENDORED PATCH — drop the already-consumed prefix of the staging buffer.
    ///
    /// Draining on every `read` would be quadratic, so this only runs once
    /// `COMPACT_AT` bytes have piled up, which amortises the copy to under one
    /// memmove per 32 KiB of input and bounds the buffer at
    /// `COMPACT_AT + max_blocksize` for the rest of the stream.
    fn compact(&mut self) {
        const COMPACT_AT: usize = 32 * 1024;
        if self.consumed < COMPACT_AT {
            return;
        }
        self.in_buf.drain(..self.consumed);
        self.skip_bits -= self.consumed * 8;
        self.consumed = 0;
    }

    /// VENDORED PATCH — test hook.
    ///
    /// The whole point of the `consumed` cursor is that this stays bounded, and
    /// a correctness test cannot tell "bounded" from "accumulates the whole
    /// stream", because both produce identical output. Callers should not use
    /// this; it exists so the test can assert the property the patch is for.
    #[doc(hidden)]
    pub fn in_buf_len(&self) -> usize {
        self.in_buf.len()
    }

    /// VENDORED PATCH — `space` must measure the *live* tail of `in_buf`, not
    /// the whole allocation, now that a consumed prefix is allowed to sit in
    /// front of it. `saturating_sub` also removes an `usize` underflow that was
    /// reachable whenever `in_buf` outgrew `max_length`: it wrapped to a huge
    /// value, which told the caller there was room to keep appending.
    fn space(&self) -> usize {
        match &self.header_block {
            Some((_, block)) if block.is_reading() => 0,
            Some((header, _)) => {
                let live = self.in_buf.len().saturating_sub(self.consumed);
                let max_length = header.max_blocksize() as usize + (self.skip_bits / 8) + 1;
                max_length.saturating_sub(live)
            }
            None => {
                Header::from_raw_blocksize(1)
                    .expect("blocksize is valid")
                    .max_blocksize() as usize
                    + 4
            }
        }
    }

    /// Write more compressed data into this [`Decoder`]
    ///
    /// See the documentation for [`WriteState`] to decide
    /// what to do next.
    pub fn write(&mut self, buf: &[u8]) -> Result<WriteState, DecoderError> {
        let space = self.space();

        match &mut self.header_block {
            Some((_, block)) if block.is_reading() => Ok(WriteState::NeedsRead),
            Some((header, block)) => {
                let written = space.min(buf.len());

                self.in_buf.extend_from_slice(&buf[..written]);

                let minimum = (self.skip_bits / 8) + header.max_blocksize() as usize;
                if buf.is_empty() || self.in_buf.len() >= minimum {
                    block.set_ready_for_read();
                }

                Ok(WriteState::Written(written))
            }
            None => {
                let written = space.min(buf.len());
                self.in_buf.extend_from_slice(&buf[..written]);

                if self.in_buf.len() < 4 {
                    return Ok(WriteState::Written(buf.len()));
                }

                let header = Header::parse(self.in_buf[..4].try_into().unwrap())?;
                let block = Block::new(header.clone());
                self.header_block = Some((header, block));

                self.skip_bits = 4 * 8;

                if written == buf.len() {
                    return Ok(WriteState::Written(written));
                }

                match self.write(&buf[written..])? {
                    WriteState::NeedsRead => unreachable!(),
                    WriteState::Written(n) => Ok(WriteState::Written(n + written)),
                }
            }
        }
    }

    /// Read more decompressed data from this [`Decoder`]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<ReadState, DecoderError> {
        match &mut self.header_block {
            Some(_) if self.eof => Ok(ReadState::Eof),
            // VENDORED PATCH — the block is done and waiting for input, so its
            // bytes are spent; drop them instead of waiting for a call that
            // cannot come.
            Some((_, block)) if block.is_not_ready() => {
                self.consumed = self.skip_bits / 8;
                self.compact();
                Ok(ReadState::NeedsWrite(self.space()))
            }
            Some((_, block)) => {
                let mut reader = BitReader::new(&self.in_buf);
                reader.advance_by(self.skip_bits);

                let ready_for_read = block.is_ready_for_read();

                let read = block.read(&mut reader, buf)?;

                if read == 0 {
                    if !buf.is_empty() {
                        self.eof = ready_for_read;
                    }

                    // VENDORED PATCH — same as above: this is the path a
                    // finished block actually takes, and it is the one upstream
                    // never accounted for.
                    self.consumed = self.skip_bits / 8;
                    self.compact();

                    return Ok(ReadState::NeedsWrite(self.space()));
                }

                if read == 0 && !buf.is_empty() {
                    self.eof = true;
                }

                self.skip_bits = reader.position();

                // VENDORED PATCH — record the cursor instead of draining here.
                if block.is_not_ready() {
                    self.consumed = self.skip_bits / 8;
                    self.compact();
                }

                Ok(ReadState::Read(read))
            }
            None => Ok(ReadState::NeedsWrite(self.space())),
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
