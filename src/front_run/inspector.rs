use alloy::primitives::U256;
use ethers_core::abi::AbiEncode;
use revm::interpreter::opcode::{LOG0, LOG1, LOG2, LOG3, LOG4};
use revm::interpreter::{opcode, CallInputs, CreateInputs, Gas, InstructionResult, Interpreter};
use revm::primitives::{keccak256, Address, Bytes, B256};
use revm::{inspectors::GasInspector, Database, EVMData, Inspector};

use crate::constants::REENTER_EVENT_TOPIC;

#[derive(Clone, Default, Debug)]
pub struct ReenterDetector {
    pub is_reenter: bool,
}

impl<DB: Database> Inspector<DB> for ReenterDetector {
    fn step(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
    ) -> InstructionResult {
        println!("{:?}", _interp.current_opcode().encode_hex());
        InstructionResult::Continue
    }
    fn log(
        &mut self,
        _evm_data: &mut EVMData<'_, DB>,
        _address: &Address,
        _topics: &[B256],
        _data: &Bytes,
    ) {
        if _topics[0].eq(&REENTER_EVENT_TOPIC.clone()) {
            self.is_reenter = true;
        }
    }
    /// Called Before the interpreter is initialized.
    ///
    /// If anything other than [InstructionResult::Continue] is returned then execution of the interpreter is
    /// skipped.
    fn initialize_interp(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
    ) -> InstructionResult {
        InstructionResult::Continue
    }

    /// Called after `step` when the instruction has been executed.
    ///
    /// InstructionResulting anything other than [InstructionResult::Continue] alters the execution of the interpreter.
    fn step_end(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, DB>,
        _eval: InstructionResult,
    ) -> InstructionResult {
        InstructionResult::Continue
    }

    /// Called whenever a call to a contract is about to start.
    ///
    /// InstructionResulting anything other than [InstructionResult::Continue] overrides the result of the call.
    fn call(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &mut CallInputs,
    ) -> (InstructionResult, Gas, Bytes) {
        (InstructionResult::Continue, Gas::new(0), Bytes::new())
    }

    /// Called when a call to a contract has concluded.
    ///
    /// InstructionResulting anything other than the values passed to this function (`(ret, remaining_gas,
    /// out)`) will alter the result of the call.
    fn call_end(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &CallInputs,
        remaining_gas: Gas,
        ret: InstructionResult,
        out: Bytes,
    ) -> (InstructionResult, Gas, Bytes) {
        (ret, remaining_gas, out)
    }

    /// Called when a contract is about to be created.
    ///
    /// InstructionResulting anything other than [InstructionResult::Continue] overrides the result of the creation.
    fn create(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &mut CreateInputs,
    ) -> (InstructionResult, Option<Address>, Gas, Bytes) {
        (
            InstructionResult::Continue,
            None,
            Gas::new(0),
            Bytes::default(),
        )
    }

    /// Called when a contract has been created.
    ///
    /// InstructionResulting anything other than the values passed to this function (`(ret, remaining_gas,
    /// address, out)`) will alter the result of the create.
    fn create_end(
        &mut self,
        _data: &mut EVMData<'_, DB>,
        _inputs: &CreateInputs,
        ret: InstructionResult,
        address: Option<Address>,
        remaining_gas: Gas,
        out: Bytes,
    ) -> (InstructionResult, Option<Address>, Gas, Bytes) {
        (ret, address, remaining_gas, out)
    }

    /// Called when a contract has been self-destructed with funds transferred to target.
    fn selfdestruct(&mut self, _contract: Address, _target: Address, _value: U256) {}
}
