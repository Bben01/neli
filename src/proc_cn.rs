//! Process Connector (proc_cn) related structures.

use neli::{
    deserialize::FromBytesWithInput,
    err::DeError,
    types::{Buffer, GenlBuffer},
    Size, ToBytes, FromBytes, Header,
};
use crate::consts::proc_cn::ProcEventType;

/// Callback Identifier for connector messages.
/// As defined in `struct cb_id` in `linux/connector.h`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
#[neli(padding = 4)] // Ensure alignment if needed, though struct cb_id has no explicit padding.
pub struct CbId {
    /// Index of the connector. For process connector, this is `CN_IDX_PROC`.
    pub idx: u32,
    /// Value associated with the index. For process connector, this is `CN_VAL_PROC`.
    pub val: u32,
}

/// Connector message structure.
/// As defined in `struct cn_msg` in `linux/connector.h`.
#[derive(Debug, Clone, PartialEq, Eq, Size, ToBytes, Header)]
pub struct CnMsg {
    /// Callback ID.
    pub id: CbId,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// Length of the payload (data).
    pub len: u16,
    /// Flags.
    pub flags: u16,
    /// Payload data.
    #[neli(input = "len")]
    pub data: Buffer<u8>,
}

impl FromBytes for CnMsg {
    fn from_bytes(buffer: &mut GenlBuffer<u8>) -> Result<Self, DeError> {
        let id = CbId::from_bytes(buffer)?;
        let seq = u32::from_bytes(buffer)?;
        let ack = u32::from_bytes(buffer)?;
        let len = u16::from_bytes(buffer)?;
        let flags = u16::from_bytes(buffer)?;
        let data = FromBytesWithInput::from_bytes_with_input(buffer, len as usize)?;
        Ok(CnMsg {
            id,
            seq,
            ack,
            len,
            flags,
            data,
        })
    }
}

// Process event data structures
// Based on struct proc_event in linux/cn_proc.h

/// Fork Process Event data.
/// `struct fork_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct ForkProcEvent {
    pub parent_pid: i32,
    pub parent_tgid: i32,
    pub child_pid: i32,
    pub child_tgid: i32,
}

/// Exec Process Event data.
/// `struct exec_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct ExecProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
}

/// UID Change Process Event data.
/// `struct uid_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct UidProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub ruid: u32, // From union: ruid or euid
    pub euid: u32,
}

/// GID Change Process Event data.
/// `struct gid_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct GidProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub rgid: u32, // From union: rgid or egid
    pub egid: u32,
}

/// SID Change Process Event data.
/// `struct sid_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct SidProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
}

/// Ptrace Process Event data.
/// `struct ptrace_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct PtraceProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub tracer_pid: i32,
    pub tracer_tgid: i32,
}

/// Comm Change Process Event data.
/// `struct comm_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct CommProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
    /// Process name, null-terminated if shorter than 16 chars.
    pub comm: [u8; 16],
}

/// Coredump Process Event data.
/// `struct coredump_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct CoredumpProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub parent_pid: i32,
    pub parent_tgid: i32,
}

/// Exit Process Event data.
/// `struct exit_proc_event`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct ExitProcEvent {
    pub process_pid: i32,
    pub process_tgid: i32,
    pub exit_code: u32,
    pub exit_signal: u32,
    pub parent_pid: i32,
    pub parent_tgid: i32,
}

/// Ack Process Event data.
/// `struct ack_proc_event` (This is not explicitly in cn_proc.h but implied by some uses of connector)
/// For process connector, the ack message is just a cn_msg with error code in data if any.
/// Let's assume the payload of an ACK is just the error code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Size, ToBytes, FromBytes)]
pub struct AckProcEvent {
    pub err: u32,
}


/// Enum representing the data for different process events.
/// This corresponds to the `union { ... } event_data;` in `struct proc_event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEventData {
    None, // For PROC_EVENT_NONE
    Fork(ForkProcEvent),
    Exec(ExecProcEvent),
    Uid(UidProcEvent),
    Gid(GidProcEvent),
    Sid(SidProcEvent),
    Ptrace(PtraceProcEvent),
    Comm(CommProcEvent),
    Coredump(CoredumpProcEvent),
    Exit(ExitProcEvent),
    // Ack is not typically part of proc_event union, it's a reply.
    // However, if we need to represent an Ack *payload* it could be here.
    // For now, let's stick to cn_proc.h events.
}

impl Size for ProcEventData {
    fn unpadded_size(&self) -> usize {
        match self {
            ProcEventData::None => 0,
            ProcEventData::Fork(e) => e.unpadded_size(),
            ProcEventData::Exec(e) => e.unpadded_size(),
            ProcEventData::Uid(e) => e.unpadded_size(),
            ProcEventData::Gid(e) => e.unpadded_size(),
            ProcEventData::Sid(e) => e.unpadded_size(),
            ProcEventData::Ptrace(e) => e.unpadded_size(),
            ProcEventData::Comm(e) => e.unpadded_size(),
            ProcEventData::Coredump(e) => e.unpadded_size(),
            ProcEventData::Exit(e) => e.unpadded_size(),
        }
    }
}

impl ToBytes for ProcEventData {
    fn to_bytes(&self, buffer: &mut GenlBuffer<u8>) -> Result<(), neli::err::SerError> {
        match self {
            ProcEventData::None => Ok(()), // No data to write
            ProcEventData::Fork(e) => e.to_bytes(buffer),
            ProcEventData::Exec(e) => e.to_bytes(buffer),
            ProcEventData::Uid(e) => e.to_bytes(buffer),
            ProcEventData::Gid(e) => e.to_bytes(buffer),
            ProcEventData::Sid(e) => e.to_bytes(buffer),
            ProcEventData::Ptrace(e) => e.to_bytes(buffer),
            ProcEventData::Comm(e) => e.to_bytes(buffer),
            ProcEventData::Coredump(e) => e.to_bytes(buffer),
            ProcEventData::Exit(e) => e.to_bytes(buffer),
        }
    }
}

impl FromBytesWithInput for ProcEventData {
    type Input = ProcEventType;

    fn from_bytes_with_input(
        buffer: &mut GenlBuffer<u8>,
        event_type: Self::Input,
    ) -> Result<Self, DeError> {
        match event_type {
            ProcEventType::None => Ok(ProcEventData::None),
            ProcEventType::Fork => Ok(ProcEventData::Fork(ForkProcEvent::from_bytes(buffer)?)),
            ProcEventType::Exec => Ok(ProcEventData::Exec(ExecProcEvent::from_bytes(buffer)?)),
            ProcEventType::Uid => Ok(ProcEventData::Uid(UidProcEvent::from_bytes(buffer)?)),
            ProcEventType::Gid => Ok(ProcEventData::Gid(GidProcEvent::from_bytes(buffer)?)),
            ProcEventType::Sid => Ok(ProcEventData::Sid(SidProcEvent::from_bytes(buffer)?)),
            ProcEventType::Ptrace => Ok(ProcEventData::Ptrace(PtraceProcEvent::from_bytes(buffer)?)),
            ProcEventType::Comm => Ok(ProcEventData::Comm(CommProcEvent::from_bytes(buffer)?)),
            ProcEventType::Coredump => Ok(ProcEventData::Coredump(CoredumpProcEvent::from_bytes(buffer)?)),
            ProcEventType::Exit => Ok(ProcEventData::Exit(ExitProcEvent::from_bytes(buffer)?)),
            ProcEventType::UnrecognizedVariant(v) => {
                Err(DeError::new(format!("Unrecognized ProcEventType variant: {}", v)))
            }
        }
    }
}


/// Main Process Event structure.
/// As defined in `struct proc_event` in `linux/cn_proc.h`.
#[derive(Debug, Clone, PartialEq, Eq, Size, ToBytes)]
pub struct ProcEvent {
    pub what: ProcEventType,
    pub cpu: u32,
    pub timestamp_ns: u64,
    #[neli(input = "what")]
    pub event_data: ProcEventData,
}

// Manual FromBytes for ProcEvent because event_data depends on 'what'
impl FromBytes for ProcEvent {
    fn from_bytes(buffer: &mut GenlBuffer<u8>) -> Result<Self, DeError> {
        let what_val = u32::from_bytes(buffer)?;
        let what = ProcEventType::from(what_val);
        let cpu = u32::from_bytes(buffer)?;
        let timestamp_ns = u64::from_bytes(buffer)?;
        let event_data = ProcEventData::from_bytes_with_input(buffer, what)?;
        Ok(ProcEvent {
            what,
            cpu,
            timestamp_ns,
            event_data,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::proc_cn::{CN_IDX_PROC, CN_VAL_PROC};
    use neli::serialize::Serializer;

    #[test]
    fn test_cb_id_serialize_deserialize() {
        let original = CbId { idx: CN_IDX_PROC, val: CN_VAL_PROC };
        let mut buffer = GenlBuffer::new_reserved(CbId::padded_size());
        original.to_bytes(&mut buffer).unwrap();
        
        let mut read_buffer = GenlBuffer::new_deserializing(&buffer.as_slice());
        let deserialized = CbId::from_bytes(&mut read_buffer).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_cn_msg_serialize_deserialize() {
        let data_payload = vec![1, 2, 3, 4, 5];
        let original = CnMsg {
            id: CbId { idx: CN_IDX_PROC, val: CN_VAL_PROC },
            seq: 12345,
            ack: 54321,
            len: data_payload.len() as u16,
            flags: 0,
            data: Buffer::from(data_payload.clone()),
        };

        let mut buffer = GenlBuffer::new_reserved(original.unpadded_size());
        original.to_bytes(&mut buffer).unwrap();
        
        let mut read_buffer = GenlBuffer::new_deserializing(&buffer.as_slice());
        let deserialized = CnMsg::from_bytes(&mut read_buffer).unwrap();
        assert_eq!(original.id, deserialized.id);
        assert_eq!(original.seq, deserialized.seq);
        assert_eq!(original.ack, deserialized.ack);
        assert_eq!(original.len, deserialized.len);
        assert_eq!(original.flags, deserialized.flags);
        assert_eq!(original.data.as_ref(), deserialized.data.as_ref());
    }
    
    fn test_proc_event_ser_de<E: Size + ToBytes + FromBytes + Copy + Clone + std::fmt::Debug + PartialEq>(
        event_type: ProcEventType,
        event_data_concrete: E,
        event_data_enum: ProcEventData,
    ) {
        let original_event = ProcEvent {
            what: event_type,
            cpu: 1,
            timestamp_ns: 1234567890,
            event_data: event_data_enum,
        };

        let mut buffer = GenlBuffer::new_reserved(original_event.unpadded_size());
        original_event.to_bytes(&mut buffer).unwrap();

        let mut read_buffer = GenlBuffer::new_deserializing(buffer.as_slice());
        let deserialized_event = ProcEvent::from_bytes(&mut read_buffer).unwrap();
        
        assert_eq!(original_event, deserialized_event);

        // Test direct event data struct if possible (though it's part of ProcEventData)
        let mut event_data_buffer = GenlBuffer::new_reserved(event_data_concrete.unpadded_size());
        event_data_concrete.to_bytes(&mut event_data_buffer).unwrap();
        let mut read_event_data_buffer = GenlBuffer::new_deserializing(event_data_buffer.as_slice());
        let deserialized_event_data = E::from_bytes(&mut read_event_data_buffer).unwrap();
        assert_eq!(event_data_concrete, deserialized_event_data);
    }

    #[test]
    fn test_fork_proc_event() {
        let event = ForkProcEvent { parent_pid: 100, parent_tgid: 100, child_pid: 200, child_tgid: 200 };
        test_proc_event_ser_de(ProcEventType::Fork, event, ProcEventData::Fork(event));
    }

    #[test]
    fn test_exec_proc_event() {
        let event = ExecProcEvent { process_pid: 123, process_tgid: 123 };
        test_proc_event_ser_de(ProcEventType::Exec, event, ProcEventData::Exec(event));
    }

    #[test]
    fn test_uid_proc_event() {
        let event = UidProcEvent { process_pid: 123, process_tgid: 123, ruid: 1000, euid: 1000 };
        test_proc_event_ser_de(ProcEventType::Uid, event, ProcEventData::Uid(event));
    }
    
    #[test]
    fn test_gid_proc_event() {
        let event = GidProcEvent { process_pid: 123, process_tgid: 123, rgid: 100, egid: 100 };
        test_proc_event_ser_de(ProcEventType::Gid, event, ProcEventData::Gid(event));
    }

    #[test]
    fn test_sid_proc_event() {
        let event = SidProcEvent { process_pid: 123, process_tgid: 123 };
        test_proc_event_ser_de(ProcEventType::Sid, event, ProcEventData::Sid(event));
    }

    #[test]
    fn test_ptrace_proc_event() {
        let event = PtraceProcEvent { process_pid: 123, process_tgid: 123, tracer_pid: 456, tracer_tgid: 456 };
        test_proc_event_ser_de(ProcEventType::Ptrace, event, ProcEventData::Ptrace(event));
    }

    #[test]
    fn test_comm_proc_event() {
        let event = CommProcEvent { process_pid: 123, process_tgid: 123, comm: *b"test_process\0\0\0\0" };
        test_proc_event_ser_de(ProcEventType::Comm, event, ProcEventData::Comm(event));
    }
    
    #[test]
    fn test_coredump_proc_event() {
        let event = CoredumpProcEvent { process_pid: 123, process_tgid: 123, parent_pid: 100, parent_tgid: 100 };
        test_proc_event_ser_de(ProcEventType::Coredump, event, ProcEventData::Coredump(event));
    }

    #[test]
    fn test_exit_proc_event() {
        let event = ExitProcEvent { process_pid: 123, process_tgid: 123, exit_code: 1, exit_signal: 0, parent_pid: 100, parent_tgid: 100 };
        test_proc_event_ser_de(ProcEventType::Exit, event, ProcEventData::Exit(event));
    }
    
    #[test]
    fn test_none_proc_event() {
        // PROC_EVENT_NONE has no specific data structure, so ProcEventData::None is used.
        // The generic test_proc_event_ser_de can't be used directly as there's no "concrete" struct for None.
        let original_event = ProcEvent {
            what: ProcEventType::None,
            cpu: 2,
            timestamp_ns: 9876543210,
            event_data: ProcEventData::None,
        };

        let mut buffer = GenlBuffer::new_reserved(original_event.unpadded_size());
        original_event.to_bytes(&mut buffer).unwrap();

        let mut read_buffer = GenlBuffer::new_deserializing(buffer.as_slice());
        let deserialized_event = ProcEvent::from_bytes(&mut read_buffer).unwrap();
        
        assert_eq!(original_event, deserialized_event);
        assert_eq!(original_event.event_data.unpadded_size(), 0);
    }

    // Test for AckProcEvent (if it were part of ProcEventData directly)
    // For now, AckProcEvent is a standalone struct not part of ProcEventData enum.
    #[test]
    fn test_ack_proc_event_standalone() {
        let original = AckProcEvent { err: 0 };
        let mut buffer = GenlBuffer::new_reserved(AckProcEvent::padded_size());
        original.to_bytes(&mut buffer).unwrap();
        
        let mut read_buffer = GenlBuffer::new_deserializing(&buffer.as_slice());
        let deserialized = AckProcEvent::from_bytes(&mut read_buffer).unwrap();
        assert_eq!(original, deserialized);

        let original_err = AckProcEvent { err: 5 }; // E.g. EPERM or some error code
        let mut buffer_err = GenlBuffer::new_reserved(AckProcEvent::padded_size());
        original_err.to_bytes(&mut buffer_err).unwrap();

        let mut read_buffer_err = GenlBuffer::new_deserializing(&buffer_err.as_slice());
        let deserialized_err = AckProcEvent::from_bytes(&mut read_buffer_err).unwrap();
        assert_eq!(original_err, deserialized_err);
    }
}
