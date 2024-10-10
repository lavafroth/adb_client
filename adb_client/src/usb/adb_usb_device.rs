use std::fs::read_to_string;
use std::path::PathBuf;

use super::ADBUsbMessage;
use crate::usb::adb_usb_message::{AUTH_RSAPUBLICKEY, AUTH_SIGNATURE, AUTH_TOKEN};
use crate::{usb::usb_commands::USBCommand, ADBTransport, Result, RustADBError, USBTransport};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use rusb::{Device, DeviceDescriptor, UsbContext};
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

    /// run shell commands on a device
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
}

impl Drop for ADBUSBDevice {
    fn drop(&mut self) {
        // Best effort here
        let _ = self.transport.disconnect();
    }
}
