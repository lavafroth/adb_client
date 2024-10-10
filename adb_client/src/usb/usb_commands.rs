use std::fmt::Display;

use serde_repr::{Deserialize_repr, Serialize_repr};
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum USBCommand {
    // Connect to a device
    Cnxn = 0x4e584e43,
    // Close connection to a device
    Clse = 0x45534c43,
    // Device ask for authentication
    Auth = 0x48545541, // OTHERS
    Sync = 0x434e5953,
    Open = 0x4e45504f,
    Okay = 0x59414b4f,
    Wrte = 0x45545257,
    Stls = 0x534C5453,
}

impl Display for USBCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            USBCommand::Cnxn => write!(f, "CNXN"),
            USBCommand::Clse => write!(f, "CLSE"),
            USBCommand::Auth => write!(f, "AUTH"),
            _ => write!(f, "ehhh"),
        }
    }
}
