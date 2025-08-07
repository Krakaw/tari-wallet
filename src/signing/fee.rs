pub struct Fee {
    /// Weight in grams per kernel
    pub kernel_weight: u64,
    /// Weight in grams per input
    pub input_weight: u64,
    /// Weight in grams per output, excl. TariScript and OutputFeatures
    pub output_weight: u64,
    /// Features and scripts per byte weight
    pub features_and_scripts_bytes_per_gram: u64,
}

impl Fee {
    pub fn new() -> Self {
        Self {
            kernel_weight: 10,
            input_weight: 8,
            output_weight: 53,
            features_and_scripts_bytes_per_gram: 16,
        }
    }

    pub fn calculate(
        &self,
        fee_per_gram: u64,
        num_kernels: usize,
        num_inputs: usize,
        num_outputs: usize,
        rounded_features_and_scripts_byte_size: usize,
    ) -> u64 {
        let weight = self.kernel_weight * num_kernels as u64
            + self.input_weight * num_inputs as u64
            + self.output_weight * num_outputs as u64
            + rounded_features_and_scripts_byte_size as u64
                / self.features_and_scripts_bytes_per_gram;

        weight.saturating_mul(fee_per_gram)
    }

    pub fn round_up_features_and_scripts_size(&self, features_and_scripts_size: usize) -> usize {
        let per_gram = self.features_and_scripts_bytes_per_gram as usize;
        let rem = features_and_scripts_size % per_gram;
        if rem == 0 {
            features_and_scripts_size
        } else {
            features_and_scripts_size
                .checked_add(per_gram - rem)
                // The maximum rounded value possible is usize::MAX - usize::MAX % per_gram
                .unwrap_or(usize::MAX - usize::MAX % per_gram)
        }
    }
}
