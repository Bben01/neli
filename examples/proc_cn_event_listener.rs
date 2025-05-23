//! Example for listening to process connector events.
//!
//! This example connects to the netlink connector interface, subscribes to
//! process events (fork, exec, exit, etc.), and prints them to the console.
//!
//! Usage:
//! ```sh
//! cargo run --example proc_cn_event_listener
//! ```
//! (You'll need to run this with appropriate permissions, likely as root or with CAP_NET_ADMIN)

use neli::{
    consts::{
        nl::{NlFamily, NlmF, Nlmsg},
        socket::NlSocketProtocol,
    },
    consts::proc_cn::{
        CN_IDX_PROC, CN_VAL_PROC, PROC_CN_MCAST_LISTEN,
        ProcEventType,
    },
    nl::{Nlmsghdr, NlmsghdrBuilder, NlPayload},
    proc_cn::{CbId, CnMsg, ProcEvent, ProcEventData},
    socket::asynchronous::NlSocket,
    types::Buffer,
    utils::Groups,
    Size, ToBytes, FromBytes,
};

use futures::stream::StreamExt;
use std::error::Error;
use std::io::Cursor; // For FromBytes on ProcEvent from Buffer

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting process event listener...");
    println!("NOTE: This program likely needs to be run as root or with CAP_NET_ADMIN.");

    // 1. Connect to the netlink socket for NETLINK_CONNECTOR
    let mut socket = NlSocket::connect(
        NlSocketProtocol::Connector, // Specify NETLINK_CONNECTOR
        None,                        // No specific PID for unicast (kernel assigns)
        Groups::empty(),             // No multicast groups to join initially via connect
    )?;
    println!("Connected to NETLINK_CONNECTOR socket.");

    // 2. Subscribe to process connector events
    let mcast_op_listen = PROC_CN_MCAST_LISTEN; // This is u32
    let cn_msg_len = std::mem::size_of::<u32>() as u16;

    // Create the CnMsg payload for subscription
    let cn_msg_payload = {
        let mut op_buf = Buffer::new();
        mcast_op_listen.to_bytes(&mut op_buf)?;

        CnMsg {
            id: CbId {
                idx: CN_IDX_PROC,
                val: CN_VAL_PROC,
            },
            seq: 1, // Sequence number for this message
            ack: 0, // No ack requested for this message itself
            len: cn_msg_len,
            flags: 0,
            data: op_buf,
        }
    };

    // Get the PID assigned to our socket by the kernel
    let pid = socket.pid().ok_or("Socket PID not found")?;

    // Create the Nlmsghdr for the subscription message
    // The total length is Nlmsghdr size + CnMsg header size + actual payload (mcast_op_listen) size.
    // CnMsg::header_size() is not directly available, but CnMsg itself implements Size.
    // The CnMsg struct *includes* its own payload (data field) for Size calculation.
    // So, nlmsg_len = Nlmsghdr size + CnMsg size (which includes its data field size).
    let nlmsg_len = Nlmsghdr::<Nlmsg, CnMsg>::header_size() + cn_msg_payload.unpadded_size();

    let nlmsghdr = NlmsghdrBuilder::default()
        .nl_len(nlmsg_len as u32)
        .nl_type(Nlmsg::Done) // Kernel uses NLMSG_DONE for proc connector subscriptions
        .nl_flags(NlmF::REQUEST)
        .nl_seq(1) // Sequence number for the netlink message
        .nl_pid(pid)
        .build()?;

    // Send the subscription message
    socket.send(&nlmsghdr, NlPayload::Payload(&cn_msg_payload)).await?;
    println!("Sent subscription message to kernel for process events.");

    // 3. Receive and process event messages in a loop
    let mut stream = socket.recv_stream();
    println!("Listening for events...");

    while let Some(Ok(nl_response)) = stream.next().await {
        let nl_header = &nl_response; // Nlmsghdr is the response itself

        if nl_header.nl_type == Nlmsg::Error {
            let err_payload: NlPayload<Nlmsg, i32> = nl_header.get_payload_as()?;
            if let NlPayload::Payload(code) = err_payload {
                eprintln!("Received netlink error message: code={}", code);
                if *code == libc::ESRCH { // No such process - typically for ACKs if seq doesn't match
                    eprintln!("Error: ESRCH. This might indicate an issue with sequence numbers or PID if it were an ACK.");
                } else if *code != 0 {
                    eprintln!("Error payload: {}", nix::errno::from_i32(-(*code as i32))));
                }
            } else {
                 eprintln!("Received netlink error message with no payload.");
            }
            continue;
        }

        if nl_header.nl_type != Nlmsg::Done {
            // Proc connector events also come as NLMSG_DONE type.
            // Other types might be control messages we are not expecting here.
            println!("Received non-Done/non-Error Nlmsghdr type: {:?}", nl_header.nl_type);
            continue;
        }

        // The payload of the Nlmsghdr is CnMsg.
        // CnMsg itself has a 'data' field which then contains the ProcEvent.
        match nl_header.get_payload_as::<CnMsg>() {
            Ok(cn_msg) => {
                // The cn_msg.data is a Buffer<u8>, parse it as ProcEvent
                let mut event_data_cursor = Cursor::new(cn_msg.data.as_ref());
                match ProcEvent::from_bytes(&mut event_data_cursor) {
                    Ok(proc_event) => {
                        // Check if cursor consumed everything, otherwise it's an error or extra data
                        if event_data_cursor.position() as usize != cn_msg.data.as_ref().len() {
                            eprintln!(
                                "Warning: Did not consume all bytes from ProcEvent data buffer. Consumed {}, total {}. Event: {:?}",
                                event_data_cursor.position(),
                                cn_msg.data.as_ref().len(),
                                proc_event.what
                            );
                        }

                        print!("[CPU {} @ {}ns] Event: {:<10} ", proc_event.cpu, proc_event.timestamp_ns, format!("{:?}", proc_event.what));
                        match proc_event.event_data {
                            ProcEventData::None => println!("(No specific data)"),
                            ProcEventData::Fork(data) => {
                                println!(
                                    "Parent: pid={}, tgid={} ==> Child: pid={}, tgid={}",
                                    data.parent_pid, data.parent_tgid, data.child_pid, data.child_tgid
                                );
                            }
                            ProcEventData::Exec(data) => {
                                println!("Process: pid={}, tgid={}", data.process_pid, data.process_tgid);
                            }
                            ProcEventData::Uid(data) => {
                                println!(
                                    "Process: pid={}, tgid={} -> ruid={}, euid={}",
                                    data.process_pid, data.process_tgid, data.ruid, data.euid
                                );
                            }
                            ProcEventData::Gid(data) => {
                                println!(
                                    "Process: pid={}, tgid={} -> rgid={}, egid={}",
                                    data.process_pid, data.process_tgid, data.rgid, data.egid
                                );
                            }
                            ProcEventData::Sid(data) => {
                                println!("Process: pid={}, tgid={} (New SID)", data.process_pid, data.process_tgid);
                            }
                            ProcEventData::Ptrace(data) => {
                                println!(
                                    "Tracer: pid={}, tgid={} tracing Process: pid={}, tgid={}",
                                    data.tracer_pid, data.tracer_tgid, data.process_pid, data.process_tgid
                                );
                            }
                            ProcEventData::Comm(data) => {
                                let comm_str = String::from_utf8_lossy(&data.comm).trim_end_matches('\0').to_string();
                                println!(
                                    "Process: pid={}, tgid={} changed name to '{}'",
                                    data.process_pid, data.process_tgid, comm_str
                                );
                            }
                            ProcEventData::Coredump(data) => {
                                println!(
                                    "Process: pid={}, tgid={} (parent: pid={}, tgid={}) coredumped",
                                    data.process_pid, data.process_tgid, data.parent_pid, data.parent_tgid
                                );
                            }
                            ProcEventData::Exit(data) => {
                                println!(
                                    "Process: pid={}, tgid={} exited with code={}, signal={}",
                                    data.process_pid, data.process_tgid, data.exit_code, data.exit_signal
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error deserializing ProcEvent from CnMsg data: {}. Data was: {:02x?}", e, cn_msg.data.as_ref());
                    }
                }
            }
            Err(e) => {
                eprintln!("Error deserializing CnMsg from Nlmsghdr payload: {}", e);
            }
        }
    }

    Ok(())
}
