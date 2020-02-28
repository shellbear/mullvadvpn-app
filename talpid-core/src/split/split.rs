use talpid_types::ErrorExt;
use regex::Regex;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command,
};

const NETCLS_PATH: &str = "/sys/fs/cgroup/net_cls/";

/// Identifies packets coming from the cgroup.
pub const NETCLS_CLASSID: u32 = 0x4d9f41;
/// Value used to mark packets and associated connections.
pub const MARK: i32 = 0xf41;

const CGROUP_NAME: &str = "mullvad-exclusions";
static mut ROUTING_TABLE_ID: i32 = 19;
const ROUTING_TABLE_NAME: &str = "mullvad_exclusions";

/// Errors related to split tunneling.
#[derive(err_derive::Error, Debug)]
#[error(no_from)]
pub enum Error {
    /// Unable to create routing table for tagged connections and packets.
    #[error(display = "Unable to create routing table")]
    RoutingTableSetup(#[error(source)] io::Error),

    /// Unable to create cgroup.
    #[error(display = "Unable to create cgroup for excluded processes")]
    CreateCGroup(#[error(source)] io::Error),

    /// Unable to set class ID for cgroup.
    #[error(display = "Unable to set cgroup class ID")]
    SetCGroupClassId(#[error(source)] io::Error),
}

fn route_marked_packets() -> Result<(), Error> {
    // TODO: IPv6
    let mut cmd = Command::new("ip");
    cmd.args(&[
        "-4",
        "rule",
        "add",
        "from", "all", "fwmark",
        &MARK.to_string(),
        "lookup",
        ROUTING_TABLE_NAME,
    ]);

    log::trace!("running cmd - {:?}", &cmd);
    cmd.output().map(|_| ()).map_err(Error::RoutingTableSetup)
}

/// Set up policy-based routing for marked packets.
pub fn initialize_routing_table() -> Result<(), Error> {
    // TODO: refactor
    // TODO: use correct error types
    // TODO: ensure the ID does not conflict with that of another table
    
    // Add routing table to /etc/iproute2/rt_tables, if it does not exist
    
    let mut file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open("/etc/iproute2/rt_tables")
        .map_err(Error::RoutingTableSetup)?;
    let buf_reader = BufReader::new(file.try_clone().map_err(Error::RoutingTableSetup)?);
    let expression = Regex::new(r"^\s*([0-9]+)\s+(\w+)")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        .map_err(Error::RoutingTableSetup)?;

    for line in buf_reader.lines() {
        let line = line.map_err(Error::RoutingTableSetup)?;
        if let Some(captures) = expression.captures(&line) {
            let table_id = captures.get(1)
                .ok_or(Error::RoutingTableSetup(io::Error::new(
                    io::ErrorKind::Other,
                    "Regex capture failed"
                )))?
                .as_str()
                .parse::<i32>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .map_err(Error::RoutingTableSetup)?;
            let table_name = captures.get(2)
                .ok_or(Error::RoutingTableSetup(io::Error::new(
                    io::ErrorKind::Other,
                    "Regex capture failed"
                )))?
                .as_str();

            // Already added
            if table_name == ROUTING_TABLE_NAME {
                if table_id != unsafe { ROUTING_TABLE_ID } {
                    unsafe { ROUTING_TABLE_ID = table_id };
                }

                return route_marked_packets();
            }
        }
    }

    let mut table_entry = String::new();
    table_entry.push_str(&unsafe { ROUTING_TABLE_ID }.to_string());
    table_entry.push_str(" ");
    table_entry.push_str(ROUTING_TABLE_NAME);
    file.write_all(table_entry.as_bytes())
        .map_err(Error::RoutingTableSetup)?;

    route_marked_packets()
}

/// Set up cgroup used to track PIDs for split tunneling.
pub fn create_cgroup() -> Result<(), Error> {
    let mut exclusions_dir = PathBuf::from(NETCLS_PATH);
    exclusions_dir.push(CGROUP_NAME);

    if !exclusions_dir.exists() {
        fs::create_dir(exclusions_dir.clone()).map_err(Error::CreateCGroup)?;
    }

    let mut classid_file = PathBuf::from(exclusions_dir);
    classid_file.push("net_cls.classid");
    fs::write(classid_file, NETCLS_CLASSID.to_string().as_bytes())
        .map_err(Error::SetCGroupClassId)
}
