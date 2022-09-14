
const DEFAULT_HART_TESTS: &str = "tests/ProcessorTests/680x0/68000/v1/";

use std::io::prelude::*;
use std::fmt::Debug;
use std::path::PathBuf;
use std::time::SystemTime;
use std::fs::{self, File};

use clap::{Parser, ArgEnum};
use flate2::read::GzDecoder;
use serde_derive::Deserialize;

use moa::error::Error;
use moa::system::System;
use moa::memory::{MemoryBlock, BusPort};
use moa::devices::{Address, Addressable, Steppable, wrap_transmutable};

use moa::cpus::m68k::{M68k, M68kType};
use moa::cpus::m68k::state::Status;

#[derive(Copy, Clone, PartialEq, Eq, ArgEnum)]
enum Selection {
    Include,
    Exclude,
    ExcludeAddr,
    Only,
}

#[derive(Parser)]
struct Args {
    /// Filter the tests by gzip file name
    filter: Option<String>,
    /// Only run the one test with the given number
    #[clap(short, long)]
    only: Option<String>,
    /// Dump the CPU state when a test fails
    #[clap(short, long)]
    debug: bool,
    /// Only print a summary for each test file
    #[clap(short, long)]
    quiet: bool,
    /// Also test instruction timing
    #[clap(short, long)]
    timing: bool,
    /// Directory to the test suite to run
    #[clap(long, default_value = DEFAULT_HART_TESTS)]
    testsuite: String,
    #[clap(long, short, arg_enum, default_value_t = Selection::Include)]
    exceptions: Selection,
}

fn main() {
    let args = Args::parse();
    run_all_tests(&args);
}


#[derive(Debug, Deserialize)]
struct TestState {
    d0: u32,
    d1: u32,
    d2: u32,
    d3: u32,
    d4: u32,
    d5: u32,
    d6: u32,
    d7: u32,
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
    a5: u32,
    a6: u32,
    usp: u32,
    ssp: u32,
    sr: u16,
    pc: u32,
    prefetch: Vec<u16>,
    ram: Vec<(u32, u8)>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    name: String,
    #[serde(rename(deserialize = "initial"))]
    initial_state: TestState,
    #[serde(rename(deserialize = "final"))]
    final_state: TestState,
    length: usize
}

impl TestState {
    pub fn dump(&self) {
        println!("d0: {:08x}    a0: {:08x}", self.d0, self.a0);
        println!("d1: {:08x}    a1: {:08x}", self.d1, self.a1);
        println!("d2: {:08x}    a2: {:08x}", self.d2, self.a2);
        println!("d3: {:08x}    a3: {:08x}", self.d3, self.a3);
        println!("d4: {:08x}    a4: {:08x}", self.d4, self.a4);
        println!("d5: {:08x}    a5: {:08x}", self.d5, self.a5);
        println!("d6: {:08x}    a6: {:08x}", self.d6, self.a6);
        println!("d7: {:08x}   usp: {:08x}", self.d7, self.usp);
        println!("pc: {:08x}   ssp: {:08x}", self.pc, self.ssp);
        println!("sr: {:04x}", self.sr);

        print!("prefetch: ");
        for word in self.prefetch.iter() {
            print!("{:04x} ", *word);
        }
        println!("");

        println!("ram: ");
        for (addr, byte) in self.ram.iter() {
            println!("{:08x} {:02x} ", *addr, *byte);
        }
    }
}

impl TestCase {
    pub fn dump(&self) {
        println!("{}", self.name);
        println!("initial:");
        self.initial_state.dump();
        println!("final:");
        self.final_state.dump();
        println!("cycles: {}", self.length);
    }

    pub fn is_exception_case(&self) -> bool {
        // If the supervisor stack changes by 6 or more bytes, then it's likely expected to be caused by an exception
        self.initial_state.ssp.saturating_sub(self.final_state.ssp) >= 6
    }

    pub fn is_extended_exception_case(&self) -> bool {
        // If the supervisor stack changes by 6 or more bytes, then it's likely expected to be caused by an exception
        self.initial_state.ssp.saturating_sub(self.final_state.ssp) >= 10
    }
}


fn init_execute_test(cputype: M68kType, state: &TestState) -> Result<(M68k, System), Error> {
    let mut system = System::new();

    // Insert basic initialization
    let data = vec![0; 0x01000000];
    let mem = MemoryBlock::new(data);
    system.add_addressable_device(0x00000000, wrap_transmutable(mem)).unwrap();

    let port = if cputype <= M68kType::MC68010 {
        BusPort::new(0, 24, 16, system.bus.clone())
    } else {
        BusPort::new(0, 32, 32, system.bus.clone())
    };
    let mut cpu = M68k::new(cputype, 10_000_000, port);
    cpu.state.status = Status::Running;

    load_state(&mut cpu, &mut system, state)?;

    Ok((cpu, system))
}

fn assert_value<T: PartialEq + Debug>(actual: T, expected: T, message: &str) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::assertion(&format!("{:?} != {:?}, {}", actual, expected, message)))
    }
}

fn load_state(cpu: &mut M68k, system: &mut System, initial: &TestState) -> Result<(), Error> {
    cpu.state.d_reg[0] = initial.d0;
    cpu.state.d_reg[1] = initial.d1;
    cpu.state.d_reg[2] = initial.d2;
    cpu.state.d_reg[3] = initial.d3;
    cpu.state.d_reg[4] = initial.d4;
    cpu.state.d_reg[5] = initial.d5;
    cpu.state.d_reg[6] = initial.d6;
    cpu.state.d_reg[7] = initial.d7;
    cpu.state.a_reg[0] = initial.a0;
    cpu.state.a_reg[1] = initial.a1;
    cpu.state.a_reg[2] = initial.a2;
    cpu.state.a_reg[3] = initial.a3;
    cpu.state.a_reg[4] = initial.a4;
    cpu.state.a_reg[5] = initial.a5;
    cpu.state.a_reg[6] = initial.a6;

    cpu.state.usp = initial.usp;
    cpu.state.ssp = initial.ssp;
    cpu.state.sr = initial.sr;
    cpu.state.pc = initial.pc;

    // Load instructions into memory
    for (i, ins) in initial.prefetch.iter().enumerate() {
        system.get_bus().write_beu16((initial.pc + (i as u32 * 2)) as u64, *ins)?;
    }

    // Load data bytes into memory
    for (addr, byte) in initial.ram.iter() {
        system.get_bus().write_u8(*addr as u64, *byte)?;
    }

    Ok(())
}

fn assert_state(cpu: &M68k, system: &System, expected: &TestState) -> Result<(), Error> {
    assert_value(cpu.state.d_reg[0], expected.d0, "d0")?;
    assert_value(cpu.state.d_reg[1], expected.d1, "d1")?;
    assert_value(cpu.state.d_reg[2], expected.d2, "d2")?;
    assert_value(cpu.state.d_reg[3], expected.d3, "d3")?;
    assert_value(cpu.state.d_reg[4], expected.d4, "d4")?;
    assert_value(cpu.state.d_reg[5], expected.d5, "d5")?;
    assert_value(cpu.state.d_reg[6], expected.d6, "d6")?;
    assert_value(cpu.state.d_reg[7], expected.d7, "d7")?;
    assert_value(cpu.state.a_reg[0], expected.a0, "a0")?;
    assert_value(cpu.state.a_reg[1], expected.a1, "a1")?;
    assert_value(cpu.state.a_reg[2], expected.a2, "a2")?;
    assert_value(cpu.state.a_reg[3], expected.a3, "a3")?;
    assert_value(cpu.state.a_reg[4], expected.a4, "a4")?;
    assert_value(cpu.state.a_reg[5], expected.a5, "a5")?;
    assert_value(cpu.state.a_reg[6], expected.a6, "a6")?;

    assert_value(cpu.state.usp, expected.usp, "usp")?;
    assert_value(cpu.state.ssp, expected.ssp, "ssp")?;
    assert_value(cpu.state.sr, expected.sr, "sr")?;
    assert_value(cpu.state.pc, expected.pc, "pc")?;

    let addr_mask = cpu.port.address_mask();

    // Load instructions into memory
    for (i, ins) in expected.prefetch.iter().enumerate() {
        let addr = expected.pc + (i as u32 * 2);
        let actual = system.get_bus().read_beu16(addr as Address & addr_mask)?;
        assert_value(actual, *ins, &format!("prefetch at {}", addr))?;
    }

    // Load data bytes into memory
    for (addr, byte) in expected.ram.iter() {
        let actual = system.get_bus().read_u8(*addr as Address & addr_mask)?;
        assert_value(actual, *byte, &format!("ram at {}", addr))?;
    }

    Ok(())
}

fn step_cpu_and_assert(cpu: &mut M68k, system: &System, case: &TestCase, test_timing: bool) -> Result<(), Error> {
    let clock_elapsed = cpu.step(&system)?;
    let cycles = clock_elapsed / (1_000_000_000 / cpu.frequency as u64);

    assert_state(&cpu, &system, &case.final_state)?;

    if test_timing {
        assert_value(cycles, case.length as u64, "clock cycles")?;
    }
    Ok(())
}

fn run_test(case: &TestCase, args: &Args) -> Result<(), Error> {
    let (mut cpu, system) = init_execute_test(M68kType::MC68000, &case.initial_state).unwrap();
    let mut initial_cpu = cpu.clone();

    let result = step_cpu_and_assert(&mut cpu, &system, case, args.timing);

    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            if !args.quiet {
                if args.debug {
                    case.dump();
                    println!("");
                    initial_cpu.dump_state();
                    cpu.dump_state();
                }
                println!("FAILED: {}",  err.msg);
            }
            Err(err)
        },
    }
}

fn test_json_file(path: PathBuf, args: &Args) -> (usize, usize, String) {
    let extension = path.extension().unwrap();

    let cases: Vec<TestCase> = if extension == "gz" {
        let file = File::open(&path).unwrap();
        let mut decoder = GzDecoder::new(file);
        let mut data = String::new();
        decoder.read_to_string(&mut data).unwrap();
        serde_json::from_str(&data).unwrap()
    } else {
        let data = fs::read(&path).unwrap();
        serde_json::from_slice(&data).unwrap()
    };

    let mut passed = 0;
    let mut failed = 0;
    for mut case in cases {
        if let Some(only) = args.only.as_ref() {
            if !case.name.ends_with(only) {
                continue;
            }
        }

        // Only run the test if it's selected by the exceptions flag
        if case.is_extended_exception_case() && args.exceptions == Selection::ExcludeAddr {
            continue;
        } else if case.is_exception_case() && args.exceptions == Selection::Exclude {
            continue;
        } else if !case.is_exception_case() && args.exceptions == Selection::Only {
            continue;
        }

        // Sort the ram memory for debugging help
        if args.debug {
            case.initial_state.ram.sort_by_key(|(addr, _)| *addr);
            case.final_state.ram.sort_by_key(|(addr, _)| *addr);
        }

        if !args.quiet {
            println!("Running test {}", case.name);
        }
        let result = run_test(&case, args);

        if let Err(err) = result {
            failed += 1;
            if !args.quiet {
                println!("FAILED: {:?}",  err);
            }
        } else {
            passed += 1
        }
    }

    let name = path.file_name().unwrap().to_str().unwrap();
    let message = if failed == 0 {
        format!("{} completed, all passed!", name)
    } else {
        format!("{} completed: {} passed, {} FAILED", name, passed, failed)
    };

    (passed, failed, message)
}


fn run_all_tests(args: &Args) {
    let mut passed = 0;
    let mut failed = 0;
    let mut messages = vec![];


    let mut tests: Vec<PathBuf> = fs::read_dir(&args.testsuite)
        .unwrap()
        .map(|dirent| dirent.unwrap().path())
        .collect();
    tests.sort();

    let start = SystemTime::now();
    for path in tests {
        // Only test gzip files (the repo has .md files as well)
        let extension = path.extension().unwrap();
        if extension != "json" && extension != "gz" {
            continue;
        }

        // If specified, only test files that start with a given string
        if let Some(filter) = &args.filter {
            if !path.file_name().unwrap().to_str().unwrap().starts_with(filter) {
                continue;
            }
        }

        // Run every test in the file
        let (test_passed, test_failed, message) = test_json_file(path, args);

        // In quiet mode, print each summary as it's received to give a progress update
        if args.quiet {
            println!("{}", message);
        }

        passed += test_passed;
        failed += test_failed;
        messages.push(message);
    }
    let elapsed_secs = start.elapsed().unwrap().as_secs();

    // Print the stored summary if not in quite mode
    if !args.quiet {
        for message in messages {
            println!("{}", message);
        }
    }

    println!("");
    println!("passed: {}, failed: {}, total {:.0}%", passed, failed, ((passed as f32) / (passed as f32 + failed as f32)) * 100.0);
    println!("completed in {}m {}s", elapsed_secs / 60, elapsed_secs % 60);
}
