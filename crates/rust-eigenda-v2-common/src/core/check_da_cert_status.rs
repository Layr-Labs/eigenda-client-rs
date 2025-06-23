use crate::ConversionError;

#[derive(Debug, PartialEq)]
pub enum CheckDACertStatus {
    NullError,
    Success,
    InvalidInclusionProof,
    SecurityAssumptionsNotMet,
    BlobQuorumsNotSubset,
    RequiredQuorumsNotSubset,
}

impl TryFrom<u8> for CheckDACertStatus {
    type Error = ConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CheckDACertStatus::NullError),
            1 => Ok(CheckDACertStatus::Success),
            2 => Ok(CheckDACertStatus::InvalidInclusionProof),
            3 => Ok(CheckDACertStatus::SecurityAssumptionsNotMet),
            4 => Ok(CheckDACertStatus::BlobQuorumsNotSubset),
            5 => Ok(CheckDACertStatus::RequiredQuorumsNotSubset),
            _ => Err(ConversionError::InvalidCheckDACertStatus(value)),
        }
    }
}
