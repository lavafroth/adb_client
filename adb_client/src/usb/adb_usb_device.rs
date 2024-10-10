use std::fs::read_to_string;
use std::io::{Cursor, Read, Seek};
use std::path::PathBuf;

use super::usb_commands::USBSubcommand;
use super::ADBUsbMessage;
use crate::usb::adb_usb_message::{AUTH_RSAPUBLICKEY, AUTH_SIGNATURE, AUTH_TOKEN};
use crate::{usb::usb_commands::USBCommand, ADBTransport, Result, RustADBError, USBTransport};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use byteorder::{LittleEndian, ReadBytesExt};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use rusb::{Device, DeviceDescriptor, UsbContext};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

/// Represent a device reached directly over USB
#[derive(Debug)]
pub struct ADBUSBDevice {
    // Raw bytes from the public key
    public_key: Vec<u8>,
    // Signing key derived from the private key for signing messages
    signing_key: SigningKey<Sha1>,
    transport: USBTransport,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatBuffer {
    subcommand: USBSubcommand,
    length: u32,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ModeFileSize {
    mode: u32,
    file_size: u32,
}

fn read_adb_private_key(private_key_path: Option<PathBuf>) -> Option<RsaPrivateKey> {
    let private_key = private_key_path.or_else(|| {
        homedir::my_home()
            .ok()?
            .map(|home| home.join(".android").join("adbkey"))
    })?;

    read_to_string(&private_key)
        .map_err(RustADBError::from)
        .and_then(|pk| Ok(RsaPrivateKey::from_pkcs8_pem(&pk)?))
        .ok()
}

fn is_adb_device<T: UsbContext>(device: &Device<T>, des: &DeviceDescriptor) -> bool {
    for n in 0..des.num_configurations() {
        let Ok(config_des) = device.config_descriptor(n) else {
            continue;
        };
        for interface in config_des.interfaces() {
            for interface_des in interface.descriptors() {
                let proto = interface_des.protocol_code();
                let class = interface_des.class_code();
                let subcl = interface_des.sub_class_code();
                if proto == 1 && ((class == 0xff && subcl == 0x42) || (class == 0xdc && subcl == 2))
                {
                    return true;
                }
            }
        }
    }
    false
}
/// Search for adb devices with known interface class and subclass values
pub fn search_adb_devices() -> Option<(u16, u16)> {
    for device in rusb::devices().unwrap().iter() {
        let Ok(des) = device.device_descriptor() else {
            continue;
        };
        if is_adb_device(&device, &des) {
            return Some((des.vendor_id(), des.product_id()));
        }
    }
    None
}

fn generate_keypair() -> Result<RsaPrivateKey> {
    log::info!("generating ephemeral RSA keypair");
    let mut rng = rand::thread_rng();
    Ok(RsaPrivateKey::new(&mut rng, 2048)?)
}

impl ADBUSBDevice {
    /// Instantiate a new [ADBUSBDevice]
    pub fn new(vendor_id: u16, product_id: u16, private_key_path: Option<PathBuf>) -> Result<Self> {
        let private_key = match read_adb_private_key(private_key_path) {
            Some(pk) => pk,
            None => generate_keypair()?,
        };

        let der_public_key = RsaPublicKey::from(&private_key).to_pkcs1_der()?;
        let mut public_key = BASE64_STANDARD.encode(der_public_key);
        public_key.push('\0');

        let signing_key = SigningKey::<Sha1>::new(private_key);
        Ok(Self {
            public_key: public_key.into_bytes(),
            signing_key,
            transport: USBTransport::new(vendor_id, product_id),
        })
    }

    /// Send initial connect
    pub fn send_connect(&mut self) -> Result<()> {
        self.transport.connect()?;

        // TO MAKE IT WORKING
        // WIRE USB DEVICE
        // IN NON ROOT RUN PROG

        let message = ADBUsbMessage::new(
            USBCommand::Cnxn,
            0x01000000,
            1048576,
            "host::pc-portable\0".into(),
        );

        self.transport.write_message(message)?;

        let message = self.transport.read_message()?;

        // At this point, we should have received either:
        // - an AUTH message with arg0 == 1
        // - a CNXN message
        let auth_message = match message.header.command {
            USBCommand::Auth if message.header.arg0 == AUTH_TOKEN => message,
            USBCommand::Auth if message.header.arg0 != AUTH_TOKEN => {
                return Err(RustADBError::ADBRequestFailed(
                    "Received AUTH message with type != 1".into(),
                ))
            }
            USBCommand::Cnxn => {
                log::info!("Successfully authenticated on device !");
                return Ok(());
            }
            _ => {
                return Err(RustADBError::ADBRequestFailed(format!(
                    "Wrong command received {}",
                    message.header.command
                )))
            }
        };

        let signed_payload = self.signing_key.try_sign(&auth_message.payload)?;
        let b = signed_payload.to_vec();

        let message = ADBUsbMessage::new(USBCommand::Auth, AUTH_SIGNATURE, 0, b);

        self.transport.write_message(message)?;

        let received_response = self.transport.read_message()?;

        println!("response after auth signature: {:?}", &received_response);

        if received_response.header.command == USBCommand::Cnxn {
            log::info!("Successfully authenticated on device !");
            return Ok(());
        }

        let message = ADBUsbMessage::new(
            USBCommand::Auth,
            AUTH_RSAPUBLICKEY,
            0,
            // TODO: Make the function accept a slice of u8
            // to avoid clone
            self.public_key.clone(),
        );

        self.transport.write_message(message)?;

        let response = self.transport.read_message()?;

        dbg!(response);

        Ok(())
    }

    /// ask the device for a file's stats
    pub fn stat(
        &mut self,
        remote_path: &str,
        local_id: u32,
        remote_id: u32,
    ) -> Result<ADBUsbMessage> {
        let stat_buffer = StatBuffer {
            subcommand: USBSubcommand::Stat,
            length: remote_path.len() as u32,
        };
        let message = ADBUsbMessage::new(
            USBCommand::Wrte,
            local_id,
            remote_id,
            bincode::serialize(&stat_buffer).map_err(|_e| RustADBError::ConversionError)?,
        );
        self.must_send(message)?;
        let message = ADBUsbMessage::new(USBCommand::Wrte, local_id, remote_id, remote_path.into());
        self.must_send(message)?;
        self.must_recv(local_id, remote_id)
    }

    /// Expect an `OKAY` after sending a message
    pub fn must_recv(&mut self, local_id: u32, remote_id: u32) -> Result<ADBUsbMessage> {
        let message = self.transport.read_message()?;
        self.transport.write_message(ADBUsbMessage::new(
            USBCommand::Okay,
            local_id,
            remote_id,
            "".into(),
        ))?;
        Ok(message)
    }

    /// Expect an `OKAY` after sending a message
    pub fn must_send(&mut self, message: ADBUsbMessage) -> Result<ADBUsbMessage> {
        self.transport.write_message(message)?;
        let message = self.transport.read_message()?;
        if message.header.command != USBCommand::Okay {
            return Err(RustADBError::ADBRequestFailed(format!(
                "expected command OKAY after sending OPEN, got {}",
                message.header.command
            )));
        }
        Ok(message)
    }

    /// pull a file from the `source` on device to `destination` on the host
    pub fn pull(&mut self, source: &str) -> Result<Vec<u8>> {
        println!("okay I'm pulling");
        self.transport.connect()?;
        let sync_directive = "sync:.\0";
        let message = ADBUsbMessage::new(USBCommand::Open, 12345, 0, sync_directive.into());

        let message = self.must_send(message)?;
        let local_id = message.header.arg1;
        let remote_id = message.header.arg0;

        println!("okay I'm stating");
        let message = self.stat(source, local_id, remote_id)?;
        let ModeFileSize { mode, file_size } = bincode::deserialize(&message.payload[4..])
            .map_err(|_e| RustADBError::ConversionError)?;

        println!("okay mode is {mode}");
        println!("okay file size is {file_size}");
        if mode == 0 {
            return Err(RustADBError::UnknownResponseType(format!(
                "expected command OKAY after sending OPEN, got {}",
                message.header.command
            )));
        }

        println!("Now I will try to send the StatBuffer AGAIN");

        let recv_buffer = StatBuffer {
            subcommand: USBSubcommand::Recv,
            length: source.len() as u32,
        };

        let recv_buffer =
            bincode::serialize(&recv_buffer).map_err(|_e| RustADBError::ConversionError)?;

        println!("recv_buffer: {recv_buffer:?}");

        self.must_send(ADBUsbMessage::new(
            USBCommand::Wrte,
            local_id,
            remote_id,
            recv_buffer,
        ))?;
        self.must_send(ADBUsbMessage::new(
            USBCommand::Wrte,
            local_id,
            remote_id,
            source.into(),
        ))?;

        let raw_data = self.recv_file(local_id, remote_id)?;
        parse_file_data(raw_data)
    }

    /// Run shell commands
    pub fn shell(&mut self, command: &str) -> Result<String> {
        self.transport.connect()?;
        let shell_string = format!("shell:{}\0", command);

        let message = ADBUsbMessage::new(USBCommand::Open, 12345, 0, shell_string.clone().into());

        self.transport.write_message(message)?;

        println!("wrote shell string: {shell_string:?}");

        let mut message = self.transport.read_message()?;

        while message.header.command == USBCommand::Clse {
            log::info!("ignoring batshit crazy commands");
            message = self.transport.read_message()?;
        }

        if message.header.command != USBCommand::Okay {
            return Err(RustADBError::ADBRequestFailed(format!(
                "expected command OKAY after sending OPEN, got {}",
                message.header.command
            )));
        }

        let local_id = message.header.arg1;
        let remote_id = message.header.arg0;

        log::debug!("got message local_id: {local_id}, remote_id: {remote_id}");

        // 4096 being the default payload size, most of the
        // time, the payload is smaller than that.
        let mut output = String::with_capacity(4096);

        loop {
            let received_response = self.transport.read_message()?;
            match received_response.header.command {
                USBCommand::Wrte => {
                    let current_chunk = std::str::from_utf8(&received_response.payload)?;
                    output.push_str(current_chunk);
                    self.transport.write_message(ADBUsbMessage::new(
                        USBCommand::Okay,
                        local_id,
                        remote_id,
                        vec![0],
                    ))?;
                }
                USBCommand::Clse => break,
                _ => {
                    return Err(RustADBError::ADBRequestFailed(format!(
                        "expected output stream to emit WRTE (write) or CLSE (close) commands, got {}",
                        message.header.command
                    )));
                }
            }
        }
        Ok(output)
    }

    fn recv_file(&mut self, local_id: u32, remote_id: u32) -> Result<Vec<u8>> {
        println!("I will try to recv the file now");
        let mut data = vec![];
        loop {
            let payload = self.must_recv(local_id, remote_id)?.into_payload();
            let done = Cursor::new(&payload[(payload.len() - 8)..]).read_u32::<LittleEndian>()?;
            println!("is it done? {done}");
            data.extend_from_slice(&payload);
            if done == USBSubcommand::Done as u32 {
                break;
            }
        }
        println!("I'm done with this file");
        Ok(data)
    }
}

fn parse_file_data(raw_data: Vec<u8>) -> Result<Vec<u8>> {
    let mut file_data = vec![];
    let mut cursor = Cursor::new(&raw_data);
    println!("buffer length is {}", raw_data.len());
    loop {
        cursor.seek_relative(4)?;
        println!("skipped 4 bytes; cursor is now at {}", cursor.position());
        // pos is now 4
        let len = cursor.read_u32::<LittleEndian>()?;
        println!("length is {len} (idk this guy might be sus)");
        if len == 0 {
            return Ok(file_data);
        }
        let mut chunk = vec![0; len as usize];
        cursor.read_exact(&mut chunk)?;
        file_data.extend(chunk);
        let done = cursor.read_u32::<LittleEndian>()?;
        cursor.seek_relative(-4)?;
        if done == USBSubcommand::Done as u32 {
            break;
        }
    }
    Ok(file_data)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecvFileDone {
    done: u32,
}

impl Drop for ADBUSBDevice {
    fn drop(&mut self) {
        // Best effort here
        let _ = self.transport.disconnect();
    }
}
