use femtos::{Frequency, Instant};

use moa_core::{Address, Addressable, Error, MemoryBlock, System, Transmutable};

use moa_m68k::{M68k, M68kType};
use moa_peripherals_motorola::MC68681;
use tracing::span;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

fn main() {
    tracing_subscriber::registry().with(CustomLayer).init();

    let mut system = System::default();

    let mut monitor = MemoryBlock::load("../../../binaries/lc-12_2/LC_Version_1_32.bin").unwrap();
    monitor.read_only();
    system.add_addressable_device(0x00000000, monitor).unwrap();

    let ram = MemoryBlock::new(vec![0; 0x00020000]);
    // ram.load_at(0, "").unwrap();
    system.add_addressable_device(0x00020000, ram).unwrap();

    let serial = MC68681::default();
    system.add_addressable_device(0x00040000, serial).unwrap();
    let cpu = M68k::from_type(M68kType::MC68008, Frequency::from_mhz(8));

    let printer = PeripheralAddressSpace {
        has_written: false,
    };
    system.add_addressable_device(0x00080000, printer).unwrap();

    // let cpu_device = Device::new(cpu);
    // let _cpu_device_id = cpu_device.id();
    system.add_interruptable_device("cpu", cpu).unwrap();

    system.run_forever().unwrap();

    // for i in 0.. 836732 {
    //     system.step_until_device(cpu_device.clone()).unwrap();
    // }

    // let mut data: [u8; 10] = [0; 10];

    // system.get_bus().read(Instant::FOREVER, 0x000046c6, data.as_mut_slice());

    // println!("Result: {:?}", data);
}

pub struct PeripheralAddressSpace {
    has_written: bool,
}

impl Addressable for PeripheralAddressSpace {
    fn size(&self) -> usize {
        0x03C08F // All peripherals after the MC68681
    }

    fn read(&mut self, clock: Instant, addr: Address, data: &mut [u8]) -> Result<(), Error> {
        if !self.has_written && addr == 0x01C000 && clock.duration_since(Instant::START) > femtos::Duration::from_millis(200) {
            data[0] = 0x60;
            self.has_written = true;
        }
        Ok(())
    }

    fn write(&mut self, _clock: Instant, _addr: Address, _data: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

impl Transmutable for PeripheralAddressSpace {
    fn as_addressable(&mut self) -> Option<&mut dyn Addressable> {
        Some(self)
    }
}

pub struct CustomLayer;

impl<S> Layer<S> for CustomLayer
where
    S: tracing::Subscriber,
    S: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut mem = MemoryVisitor::new();
        event.record(&mut mem);
        mem.print();
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let span = ctx.span(id).unwrap();
        match span.name() {
            "pc" => {
                println!();
                let mut visitor = PCVisitor::new();
                attrs.record(&mut visitor);
                visitor.print();
            },
            "read" => {
                let mut visitor = ReadVisitor::new();
                attrs.record(&mut visitor);
                visitor.print();
            },
            "write" => {
                let mut visitor = WriteVisitor::new();
                attrs.record(&mut visitor);
                visitor.print();
            },
            _ => (),
        }
    }
}

struct PCVisitor {
    pc: Option<u64>,
    inst: Option<String>,
    ssp: Option<u64>,
}

impl PCVisitor {
    fn new() -> Self {
        Self {
            pc: None,
            inst: None,
            ssp: None,
        }
    }

    fn print(&self) {
        print!(
            "{:#010X}\t{:<40}\t({:#010X})\t",
            self.pc.unwrap_or_default(),
            self.inst.as_ref().unwrap_or(&"".to_owned()),
            self.ssp.unwrap_or_default()
        );
    }
}

impl tracing::field::Visit for PCVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "count" {
            self.pc = Some(value);
        } else if field.name() == "ssp" {
            self.ssp = Some(value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "instruction" {
            self.inst = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        print!("PCVisitor {:?}", value);
    }
}

struct ReadVisitor {
    addr: Option<u64>,
    val: Option<u64>,
    size: Option<String>,
}

impl ReadVisitor {
    fn new() -> Self {
        Self {
            addr: None,
            val: None,
            size: None,
        }
    }

    fn print(&self) {
        let addr = self.addr.unwrap_or_default();
        print!(
            "<= {:#010X} ({:<7}) ({:#010X}.{}) ",
            addr,
            get_name_for_addr(addr),
            self.val.unwrap_or_default(),
            self.size.as_ref().unwrap_or(&"".to_owned())
        );
    }
}

impl tracing::field::Visit for ReadVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "addr" => self.addr = Some(value),
            "val" => self.val = Some(value),
            _ => (),
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "size" {
            self.size = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        print!("ReadVisitor {:?}", value);
    }
}

struct WriteVisitor {
    addr: Option<u64>,
    val: Option<u64>,
    size: Option<String>,
}

impl WriteVisitor {
    fn new() -> Self {
        Self {
            addr: None,
            val: None,
            size: None,
        }
    }

    fn print(&self) {
        let addr = self.addr.unwrap_or_default();
        print!(
            "=> {:#010X} ({:<7}) ({:#010X}.{}) ",
            addr,
            get_name_for_addr(addr),
            self.val.unwrap_or_default(),
            self.size.as_ref().unwrap_or(&"".to_owned())
        );
    }
}

impl tracing::field::Visit for WriteVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "addr" => self.addr = Some(value),
            "value" => self.val = Some(value),
            _ => (),
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "size" {
            self.size = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        print!("WriteVisitor {:?}", value);
    }
}

fn get_name_for_addr(addr: u64) -> &'static str {
    match addr {
        0x000000..=0x01FFFF => "EEPROM",
        0x020000..=0x03FFFF => "RAM",
        0x040000..=0x07FFFF => "MC68681",
        0x080000..=0x083FFF => "CS_LCD",
        0x084000..=0x087FFF => "574_DA",
        0x088000..=0x08BFFF => "574_SSM",
        0x08C000..=0x08FFFF => "CS_CARD",
        0x090000..=0x093FFF => "TAST_1",
        0x094000..=0x097FFF => "TAST_2",
        0x098000..=0x09BFFF => "TAST_3",
        0x09C000..=0x09FFFF => "TAST_4",
        0x0A0000..=0x0A3FFF => "CS_ENC",
        0x0A4000..=0x0A7FFF => "LED_1",
        0x0A8000..=0x0ABFFF => "LED_2",
        0x0AC000..=0x0AFFFF => "LED_3",
        0x0B0000..=0x0B3FFF => "LED_4",
        0x0B4000..=0x0B7FFF => "AD_WR",
        0x0B8000..=0x0BBFFF => "AD_RD",
        0x0BC000..=0x0BFFFF => "574_AD",
        _ => "UNKNOWN",
    }
}

struct MemoryVisitor {
    message: Option<String>,
}

impl MemoryVisitor {
    fn new() -> Self {
        Self {
            message: None,
        }
    }

    fn print(&self) {
        if self.message.is_some() {
            print!("MEM {} ", self.message.as_ref().unwrap_or(&"".to_owned()));
        }
    }
}

impl tracing::field::Visit for MemoryVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        print!("MemoryVisitor {:?}", value);
    }
}
