//! pcapng writer for the TUN-boundary capture tap.
//!
//! Frames are raw IP packets (LINKTYPE_RAW / DLT_RAW = 101) since the tunnel has
//! no link layer. Choosing pcapng now lets P2 attach a TLS keylog block so
//! Wireshark can decrypt MITM'd flows. An optional byte cap bounds the output.

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;

pub struct PcapWriter<W: Write> {
    writer: PcapNgWriter<W>,
    snaplen: u32,
    written: u64,
    cap: Option<u64>,
    stopped: bool,
}

impl<W: Write> PcapWriter<W> {
    /// Create a writer, emitting the section header and a single RAW interface.
    /// `cap` bounds total bytes written (packets are dropped once exceeded).
    pub fn new(inner: W, snaplen: u32, cap: Option<u64>) -> std::io::Result<Self> {
        let mut writer = PcapNgWriter::new(inner).map_err(to_io)?;
        let idb = InterfaceDescriptionBlock {
            linktype: DataLink::RAW,
            snaplen,
            options: vec![],
        };
        let n = writer.write_pcapng_block(idb).map_err(to_io)?;
        Ok(PcapWriter { writer, snaplen, written: n as u64, cap, stopped: false })
    }

    /// Append one packet captured at `ts` (since the epoch). Truncates to
    /// `snaplen`. Silently no-ops once the byte cap is reached.
    pub fn write_packet(&mut self, ts: Duration, packet: &[u8]) -> std::io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        let cap_len = packet.len().min(self.snaplen as usize);
        let block = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: ts,
            original_len: packet.len() as u32,
            data: Cow::Borrowed(&packet[..cap_len]),
            options: vec![],
        };
        let n = self.writer.write_pcapng_block(block).map_err(to_io)?;
        self.written += n as u64;
        if let Some(cap) = self.cap {
            if self.written >= cap {
                self.stopped = true;
            }
        }
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn is_full(&self) -> bool {
        self.stopped
    }

    pub fn into_inner(self) -> W {
        self.writer.into_inner()
    }
}

fn to_io(e: pcap_file::PcapError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcapng::{Block, PcapNgReader};

    #[test]
    fn round_trips_two_packets() {
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf, 65535, None).unwrap();
            w.write_packet(Duration::from_millis(1000), &[0x45, 0, 0, 20]).unwrap();
            w.write_packet(Duration::from_millis(2000), &[0x60, 0, 0, 0, 0, 0]).unwrap();
        }

        let mut reader = PcapNgReader::new(buf.as_slice()).unwrap();
        let mut packets = 0;
        while let Some(block) = reader.next_block() {
            if let Block::EnhancedPacket(_) = block.unwrap() {
                packets += 1;
            }
        }
        assert_eq!(packets, 2);
    }

    #[test]
    fn honors_byte_cap() {
        let mut buf = Vec::new();
        let mut w = PcapWriter::new(&mut buf, 65535, Some(1)).unwrap();
        // The section header + IDB already exceed 1 byte, so the first packet
        // trips the cap and subsequent writes no-op.
        w.write_packet(Duration::from_millis(1), &[0x45; 40]).unwrap();
        assert!(w.is_full());
        let before = w.bytes_written();
        w.write_packet(Duration::from_millis(2), &[0x45; 40]).unwrap();
        assert_eq!(w.bytes_written(), before);
    }
}
