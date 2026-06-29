pub mod unprotected_mutation;
pub mod mapping_overwrite;
pub mod unsafe_transfer;
pub mod reentrancy;
pub mod unchecked_unwrap;
pub mod arithmetic_overflow;
pub mod hardcoded_keys;
pub mod cep18_compliance;
pub mod divide_by_zero;
pub mod timestamp_dependence;
pub mod tainted_input;

use crate::engine::Detector;

pub fn get_all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(unprotected_mutation::UnprotectedMutationDetector),
        Box::new(mapping_overwrite::MappingOverwriteDetector),
        Box::new(unsafe_transfer::UnsafeTransferDetector),
        Box::new(reentrancy::ReentrancyDetector),
        Box::new(unchecked_unwrap::UncheckedUnwrapDetector),
        Box::new(arithmetic_overflow::ArithmeticOverflowDetector),
        Box::new(hardcoded_keys::HardcodedKeysDetector),
        Box::new(cep18_compliance::Cep18ComplianceDetector),
        Box::new(divide_by_zero::DivideByZeroDetector),
        Box::new(timestamp_dependence::TimestampDependenceDetector),
        Box::new(tainted_input::TaintedInputDetector),
    ]
}
