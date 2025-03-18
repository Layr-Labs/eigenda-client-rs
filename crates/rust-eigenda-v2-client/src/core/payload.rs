pub struct Payload {
    bytes: Vec<u8>,
}

impl Payload {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }
}
