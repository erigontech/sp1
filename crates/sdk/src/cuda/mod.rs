//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

/// The builder for the CUDA prover.
pub mod builder;
/// The CUDA prove request type.
pub mod prove;

use crate::{
    prover::{BaseProveRequest, Prover, SendFutureResult},
    utils::proof_mode,
    ProvingKey, SP1ProofMode, SP1ProofWithPublicValues,
};

use prove::CudaProveRequest;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::{CudaClientError, CudaProver as CudaProverImpl, CudaProvingKey};
use sp1_primitives::Elf;
use sp1_prover::{
    worker::{SP1LightNode, SP1NodeCore},
    SP1VerifyingKey,
};

/// A prover that uses the CPU for execution and the CUDA for proving.
#[derive(Clone)]
pub struct CudaProver {
    pub(crate) node: SP1LightNode,
    pub(crate) prover: CudaProverImpl,
}

impl Prover for CudaProver {
    type ProvingKey = CudaProvingKey;
    type Error = CudaClientError;
    type ProveRequest<'a> = CudaProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.node.inner()
    }

    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        self.prover.setup(elf)
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CudaProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}

impl CudaProver {
    /// Prove and return the cycle count alongside the proof.
    pub async fn prove_with_cycles(
        &self,
        pk: &CudaProvingKey,
        stdin: SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<(SP1ProofWithPublicValues, u64), CudaClientError> {
        let context = sp1_core_executor::SP1ContextBuilder::new().build();
        tracing::info!(?mode, "starting proof generation");
        let network_proof =
            self.prover.prove_with_mode(pk, stdin, context, proof_mode(mode)).await?;
        let cycle_count = network_proof.cycle_count;
        Ok((network_proof.into(), cycle_count))
    }
}

impl ProvingKey for CudaProvingKey {
    fn elf(&self) -> &Elf {
        self.elf()
    }

    fn verifying_key(&self) -> &SP1VerifyingKey {
        self.verifying_key()
    }
}
