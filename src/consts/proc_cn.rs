//! Constants related to the Process Connector (proc_cn)

// Constants from linux/connector.h
/// Connector Index for Process Connector
pub const CN_IDX_PROC: u32 = 1;
/// Connector Value for Process Connector
pub const CN_VAL_PROC: u32 = 1;

// Constants from linux/cn_proc.h
/// Multicast group for listening to process events
pub const PROC_CN_MCAST_LISTEN: u32 = 1;
/// Multicast group for ignoring process events
pub const PROC_CN_MCAST_IGNORE: u32 = 2;

/// Enum for Process Event types (`proc_event.what`)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum ProcEventType {
    /// No event
    None = 0, // PROC_EVENT_NONE
    /// Fork event
    Fork = 1, // PROC_EVENT_FORK
    /// Exec event
    Exec = 2, // PROC_EVENT_EXEC
    /// UID change event
    Uid = 4, // PROC_EVENT_UID
    /// GID change event
    Gid = 64, // PROC_EVENT_GID
    /// SID change event (Session ID)
    Sid = 128, // PROC_EVENT_SID
    /// Ptrace event
    Ptrace = 256, // PROC_EVENT_PTRACE
    /// Comm change event (process name)
    Comm = 512, // PROC_EVENT_COMM
    /// Coredump event
    Coredump = 1073741824, // PROC_EVENT_COREDUMP
    /// Exit event
    Exit = 2147483648, // PROC_EVENT_EXIT
    /// Unrecognized variant
    UnrecognizedVariant(u32),
}

impl From<u32> for ProcEventType {
    fn from(val: u32) -> Self {
        match val {
            0 => ProcEventType::None,
            1 => ProcEventType::Fork,
            2 => ProcEventType::Exec,
            4 => ProcEventType::Uid,
            64 => ProcEventType::Gid,
            128 => ProcEventType::Sid,
            256 => ProcEventType::Ptrace,
            512 => ProcEventType::Comm,
            1073741824 => ProcEventType::Coredump,
            2147483648 => ProcEventType::Exit,
            v => ProcEventType::UnrecognizedVariant(v),
        }
    }
}

impl From<ProcEventType> for u32 {
    fn from(val: ProcEventType) -> Self {
        match val {
            ProcEventType::None => 0,
            ProcEventType::Fork => 1,
            ProcEventType::Exec => 2,
            ProcEventType::Uid => 4,
            ProcEventType::Gid => 64,
            ProcEventType::Sid => 128,
            ProcEventType::Ptrace => 256,
            ProcEventType::Comm => 512,
            ProcEventType::Coredump => 1073741824,
            ProcEventType::Exit => 2147483648,
            ProcEventType::UnrecognizedVariant(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_event_type_from_u32() {
        assert_eq!(ProcEventType::from(0), ProcEventType::None);
        assert_eq!(ProcEventType::from(1), ProcEventType::Fork);
        assert_eq!(ProcEventType::from(2), ProcEventType::Exec);
        assert_eq!(ProcEventType::from(4), ProcEventType::Uid);
        assert_eq!(ProcEventType::from(64), ProcEventType::Gid);
        assert_eq!(ProcEventType::from(128), ProcEventType::Sid);
        assert_eq!(ProcEventType::from(256), ProcEventType::Ptrace);
        assert_eq!(ProcEventType::from(512), ProcEventType::Comm);
        assert_eq!(ProcEventType::from(1073741824), ProcEventType::Coredump);
        assert_eq!(ProcEventType::from(2147483648), ProcEventType::Exit);
        assert_eq!(ProcEventType::from(0x12345678), ProcEventType::UnrecognizedVariant(0x12345678));
    }

    #[test]
    fn test_proc_event_type_into_u32() {
        assert_eq!(u32::from(ProcEventType::None), 0);
        assert_eq!(u32::from(ProcEventType::Fork), 1);
        assert_eq!(u32::from(ProcEventType::Exec), 2);
        assert_eq!(u32::from(ProcEventType::Uid), 4);
        assert_eq!(u32::from(ProcEventType::Gid), 64);
        assert_eq!(u32::from(ProcEventType::Sid), 128);
        assert_eq!(u32::from(ProcEventType::Ptrace), 256);
        assert_eq!(u32::from(ProcEventType::Comm), 512);
        assert_eq!(u32::from(ProcEventType::Coredump), 1073741824);
        assert_eq!(u32::from(ProcEventType::Exit), 2147483648);
        assert_eq!(u32::from(ProcEventType::UnrecognizedVariant(0x12345678)), 0x12345678);
    }
}
