
#[macro_use]
mod error;
mod memory;
mod timers;
mod cpus;
mod peripherals;
mod system;

use crate::memory::MemoryBlock;
use crate::cpus::m68k::MC68010;
use crate::peripherals::ata::AtaDevice;
use crate::peripherals::mc68681::MC68681;
use crate::system::{System};

fn main() {
    let mut system = System::new();

    let monitor = MemoryBlock::load("binaries/monitor.bin").unwrap();
    for byte in monitor.contents.iter() {
        print!("{:02x} ", byte);
    }
    system.add_device(0x00000000, Box::new(monitor)).unwrap();

    let mut ram = MemoryBlock::new(vec![0; 0x00100000]);
    ram.load_at(0, "binaries/kernel.bin").unwrap();
    system.add_device(0x00100000, Box::new(ram)).unwrap();

    let mut ata = AtaDevice::new();
    ata.load("binaries/disk-with-partition-table.img").unwrap();
    system.add_device(0x00600000, Box::new(ata)).unwrap();

    let mut serial = MC68681::new();
    serial.open().unwrap();
    system.add_device(0x00700000, Box::new(serial)).unwrap();


    let mut cpu = MC68010::new();

    //cpu.enable_tracing();
    //cpu.add_breakpoint(0x0c94);
    //cpu.add_breakpoint(0x103234);
    //cpu.add_breakpoint(0x224);
    //cpu.add_breakpoint(0x100334);

    while cpu.is_running() {
        system.step().unwrap();
        match cpu.step(&system) {
            Ok(()) => { },
            Err(err) => {
                cpu.dump_state(&system);
                panic!("{:?}", err);
            },
        }

        //serial.step();
    }

    /*
    // TODO I need to add a way to decode and dump the assembly for a section of code, in debugger
    cpu.state.pc = 0x00100000;
    cpu.state.pc = 0x0010c270;
    while cpu.is_running() {
        match cpu.decode_next(&mut space) {
            Ok(()) => { },
            Err(err) => {
                cpu.dump_state(&mut space);
                panic!("{:?}", err);
            },
        }
    }
    */
}

