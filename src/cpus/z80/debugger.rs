
use crate::error::Error;
use crate::system::System;
use crate::devices::{Address, Addressable, Debuggable};

use super::state::Z80;
use super::decode::Z80Decoder;


pub struct Z80Debugger {
    pub breakpoints: Vec<u16>,
}

impl Z80Debugger {
    pub fn new() -> Self {
        Self {
            breakpoints: vec!(),
        }
    }
}

impl Debuggable for Z80 {
    fn add_breakpoint(&mut self, addr: Address) {
        self.debugger.breakpoints.push(addr as u16);
    }

    fn remove_breakpoint(&mut self, addr: Address) {
        if let Some(index) = self.debugger.breakpoints.iter().position(|a| *a == addr as u16) {
            self.debugger.breakpoints.remove(index);
        }
    }

    fn print_current_step(&mut self, system: &System) -> Result<(), Error> {
        self.decoder.decode_at(&mut self.port, self.state.pc)?;
        self.decoder.dump_decoded(&mut self.port);
        self.dump_state(system);
        Ok(())
    }

    fn print_disassembly(&mut self, addr: Address, count: usize) {
        let mut decoder = Z80Decoder::new();
        //decoder.dump_disassembly(&mut self.port, self.state.pc, 0x1000);
    }

    fn execute_command(&mut self, system: &System, args: &[&str]) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Z80 {
    pub fn check_breakpoints(&mut self, system: &System) {
        for breakpoint in &self.debugger.breakpoints {
            if *breakpoint == self.state.pc {
                println!("Breakpoint reached: {:08x}", *breakpoint);
                system.enable_debugging();
                break;
            }
        }
    }
}

