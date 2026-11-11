//! Process-to-network socket mapping using Windows IP Helper API.

use aegis_common::types::*;
use std::collections::HashMap;

pub struct NetworkSentinel;

impl NetworkSentinel {
    pub fn list_connections(process_names: &HashMap<u32, String>) -> Vec<ConnectionInfo> {
        #[cfg(windows)]
        {
            Self::list_connections_windows(process_names)
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    #[cfg(windows)]
    fn list_connections_windows(process_names: &HashMap<u32, String>) -> Vec<ConnectionInfo> {
        use windows_sys::Win32::Foundation::*;
        use windows_sys::Win32::NetworkManagement::IpHelper::*;
        use windows_sys::Win32::Networking::WinSock::*;

        let mut connections = Vec::new();
        let mut buffer_size = 0u32;

        unsafe {
            // First call to determine required buffer size
            let ret = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut buffer_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != ERROR_INSUFFICIENT_BUFFER {
                return connections;
            }

            let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
            let ret = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut buffer_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret == NO_ERROR {
                let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let num_entries = (*table).dwNumEntries;
                let rows_ptr = std::ptr::addr_of!((*table).table) as *const MIB_TCPROW_OWNER_PID;

                for i in 0..num_entries {
                    let row = *rows_ptr.add(i as usize);
                    let pid = row.dwOwningPid;

                    let local_ip = std::net::Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                    let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);

                    let remote_ip = std::net::Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                    let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);

                    let state_str = match row.dwState {
                        1 => "CLOSED",
                        2 => "LISTEN",
                        3 => "SYN_SENT",
                        4 => "SYN_RCVD",
                        5 => "ESTABLISHED",
                        6 => "FIN_WAIT1",
                        7 => "FIN_WAIT2",
                        8 => "CLOSE_WAIT",
                        9 => "CLOSING",
                        10 => "LAST_ACK",
                        11 => "TIME_WAIT",
                        12 => "DELETE_TCB",
                        _ => "UNKNOWN",
                    };

                    let is_private = local_ip.is_private() || remote_ip.is_private() || remote_ip.is_loopback();
                    let proc_name = process_names.get(&pid).cloned();

                    connections.push(ConnectionInfo {
                        protocol: "TCP".into(),
                        local_addr: local_ip.to_string(),
                        local_port,
                        remote_addr: Some(remote_ip.to_string()),
                        remote_port: Some(remote_port),
                        state: state_str.into(),
                        pid,
                        process_name: proc_name,
                        process_path: None,
                        reputation: Reputation::Unknown, // Unknown does not mean malicious
                        reputation_reason: None,
                        is_private_remote: is_private,
                    });
                }
            }
        }

        connections
    }
}

