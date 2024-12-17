/* Orchid - WebRTC P2P VPN Market (on Ethereum)
 * Copyright (C) 2017-2020  The Orchid Authors
*/

/* GNU Affero General Public License, Version 3 {{{ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */


type Output = extern "C" fn(baton: *mut std::ffi::c_void, data: *const u8, size: usize);


#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct riscy_Level {
    pub repr: u8,
}

impl riscy_Level {
    pub const COMPOSITE: Self = riscy_Level { repr: 0 };
    pub const SUCCINCT: Self = riscy_Level { repr: 1 };
    pub const GROTH16: Self = riscy_Level { repr: 2 };
}

fn delev(level: riscy_Level) -> risc0_zkvm::ProverOpts {
    match level {
        riscy_Level::COMPOSITE => risc0_zkvm::ProverOpts::composite(),
        riscy_Level::SUCCINCT => risc0_zkvm::ProverOpts::succinct(),
        riscy_Level::GROTH16 => risc0_zkvm::ProverOpts::groth16(),
        _ => panic!("unknown level"),
    }
}


fn devec(data: &cxx::CxxVector<cxx::CxxString>) -> Vec<String> {
    data.iter().map(|value| value.to_str().unwrap().to_owned()).collect()
}


#[no_mangle]
pub extern "C" fn riscy_image(
    elf: &cxx::CxxString,
    image_data: &mut [u8; 32]
) {
    let image = risc0_zkvm::compute_image_id(elf.as_bytes()).unwrap();
    image_data.copy_from_slice(image.as_bytes());
}

fn riscy_env<'a>(
    assumptions: &'a cxx::CxxVector<cxx::CxxString>,
    arguments: &'a cxx::CxxVector<cxx::CxxString>
) -> risc0_zkvm::ExecutorEnv<'a> {
    let mut builder = risc0_zkvm::ExecutorEnv::builder();

    builder.stdin(std::io::stdin());
    builder.stdout(std::io::stdout());
    builder.stderr(std::io::stderr());

    for assumption in assumptions.iter() {
        let receipt: risc0_zkvm::Receipt = bincode::deserialize(assumption.as_bytes()).unwrap();
        builder.add_assumption(receipt);
    }

    builder.args(&devec(arguments));

    builder.build().unwrap()
}

#[no_mangle]
pub extern "C" fn riscy_execute(
    elf: &cxx::CxxString,
    assumptions: &cxx::CxxVector<cxx::CxxString>,
    arguments: &cxx::CxxVector<cxx::CxxString>,
    journal_code: Output, journal_data: *mut std::ffi::c_void
) {
    let env = riscy_env(assumptions, arguments);
    let executor = risc0_zkvm::default_executor();
    let info = executor.execute(env, elf.as_bytes()).unwrap();
    let journal = info.journal.bytes;
    journal_code(journal_data, journal.as_ptr(), journal.len());
}

#[no_mangle]
pub extern "C" fn riscy_prove(
    level: riscy_Level,
    elf: &cxx::CxxString,
    assumptions: &cxx::CxxVector<cxx::CxxString>,
    arguments: &cxx::CxxVector<cxx::CxxString>,
    receipt_code: Output, receipt_data: *mut std::ffi::c_void
) {
    let env = riscy_env(assumptions, arguments);
    let prover = risc0_zkvm::default_prover();
    let info = prover.prove_with_opts(env, elf.as_bytes(), &delev(level)).unwrap();
    let receipt = bincode::serialize(&info.receipt).unwrap();
    receipt_code(receipt_data, receipt.as_ptr(), receipt.len());
}

#[no_mangle]
pub extern "C" fn riscy_compress(
    level: riscy_Level,
    assumption: &cxx::CxxString,
    receipt_code: Output, receipt_data: *mut std::ffi::c_void
) {
    let prover = risc0_zkvm::default_prover();
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(assumption.as_bytes()).unwrap();
    let receipt = prover.compress(&delev(level), &receipt).unwrap();
    let receipt = bincode::serialize(&receipt).unwrap();
    receipt_code(receipt_data, receipt.as_ptr(), receipt.len());
}

#[no_mangle]
pub extern "C" fn riscy_verify(
    image: &[u8; 32],
    assumption: &cxx::CxxString,
    journal_code: Output, journal_data: *mut std::ffi::c_void
) {
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(assumption.as_bytes()).unwrap();
    receipt.verify(*image).unwrap();
    let journal = receipt.journal.bytes;
    journal_code(journal_data, journal.as_ptr(), journal.len());
}
