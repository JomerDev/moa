
use std::iter::Iterator;
use std::sync::{Arc, Mutex};

use crate::error::Error;
use crate::system::System;
use crate::signals::SyncSignal;
use crate::devices::{Clock, ClockElapsed, Address, Addressable, Steppable, Transmutable, read_beu16, read_beu32, write_beu16};
use crate::host::traits::{Host, BlitableSurface};
use crate::host::gfx::{Frame, FrameSwapper};


const REG_MODE_SET_1: usize             = 0x00;
const REG_MODE_SET_2: usize             = 0x01;
const REG_SCROLL_A_ADDR: usize          = 0x02;
const REG_WINDOW_ADDR: usize            = 0x03;
const REG_SCROLL_B_ADDR: usize          = 0x04;
const REG_SPRITES_ADDR: usize           = 0x05;
// Register 0x06 Unused
const REG_BACKGROUND: usize             = 0x07;
// Register 0x08 Unused
// Register 0x09 Unused
const REG_H_INTERRUPT: usize            = 0x0A;
const REG_MODE_SET_3: usize             = 0x0B;
const REG_MODE_SET_4: usize             = 0x0C;
const REG_HSCROLL_ADDR: usize           = 0x0D;
// Register 0x0E Unused
const REG_AUTO_INCREMENT: usize         = 0x0F;
const REG_SCROLL_SIZE: usize            = 0x10;
const REG_WINDOW_H_POS: usize           = 0x11;
const REG_WINDOW_V_POS: usize           = 0x12;
const REG_DMA_COUNTER_LOW: usize        = 0x13;
const REG_DMA_COUNTER_HIGH: usize       = 0x14;
const REG_DMA_ADDR_LOW: usize           = 0x15;
const REG_DMA_ADDR_MID: usize           = 0x16;
const REG_DMA_ADDR_HIGH: usize          = 0x17;


const STATUS_PAL_MODE: u16              = 0x0001;
const STATUS_DMA_BUSY: u16              = 0x0002;
const STATUS_IN_HBLANK: u16             = 0x0004;
const STATUS_IN_VBLANK: u16             = 0x0008;
const STATUS_ODD_FRAME: u16             = 0x0010;
const STATUS_SPRITE_COLLISION: u16      = 0x0020;
const STATUS_SPRITE_OVERFLOW: u16       = 0x0040;
const STATUS_V_INTERRUPT: u16           = 0x0080;
const STATUS_FIFO_FULL: u16             = 0x0100;
const STATUS_FIFO_EMPTY: u16            = 0x0200;

const MODE1_BF_ENABLE_HV_COUNTER: u8    = 0x02;
const MODE1_BF_HSYNC_INTERRUPT: u8      = 0x10;

const MODE2_BF_V_CELL_MODE: u8          = 0x08;
const MODE2_BF_VSYNC_INTERRUPT: u8      = 0x20;

const MODE3_BF_EXTERNAL_INTERRUPT: u8   = 0x08;

const MODE4_BF_H_CELL_MODE: u8          = 0x01;
const MODE4_BF_SHADOW_HIGHLIGHT: u8     = 0x08;



const DEV_NAME: &'static str = "ym7101";


#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DmaType {
    None,
    Memory,
    Fill,
    Copy,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TargetType {
    Vram,
    Cram,
    Vsram,
}

pub struct Ym7101State {
    pub status: u16,
    pub regs: [u8; 24],
    pub vram: [u8; 0x10000],
    pub cram: [u8; 128],
    pub vsram: [u8; 80],
    pub transfer_type: u8,
    pub transfer_addr: u32,
    pub transfer_fill: u16,
    pub transfer_run: DmaType,
    pub transfer_target: TargetType,
    pub transfer_upper: Option<u16>,

    pub last_clock: Clock,
    pub h_clock: u32,
    pub v_clock: u32,
    pub h_scanlines: u8,
}

impl Ym7101State {
    pub fn new() -> Self {
        Self {
            status: 0x3400 | STATUS_FIFO_EMPTY,
            regs: [0; 24],
            vram: [0; 0x10000],
            cram: [0; 128],
            vsram: [0; 80],
            transfer_type: 0,
            transfer_addr: 0,
            transfer_fill: 0,
            transfer_run: DmaType::None,
            transfer_target: TargetType::Vram,
            transfer_upper: None,

            last_clock: 0,
            h_clock: 0,
            v_clock: 0,
            h_scanlines: 0,
        }
    }

    fn set_register(&mut self, data: u16) {
        let reg = (data & 0x1F00) >> 8;
        self.regs[reg as usize] = (data & 0x00FF) as u8;
        info!("{}: register {:x} set to {:x}", DEV_NAME, reg, self.regs[reg as usize]);
    }

    pub fn set_dma_mode(&mut self, mode: DmaType) {
        match mode {
            DmaType::None => {
                self.status &= !STATUS_DMA_BUSY;
                self.transfer_run = DmaType::None;
            },
            _ => {
                self.status |= STATUS_DMA_BUSY;
                self.transfer_run = mode;
            },
        }
    }

    pub fn get_dma_src_addr(&mut self) -> u32 {
        let src_addr = (((self.regs[REG_DMA_ADDR_HIGH] & 0x7F) as u32) << 17)
                       | ((self.regs[REG_DMA_ADDR_MID] as u32) << 9)
                       | ((self.regs[REG_DMA_ADDR_LOW] as u32) << 1);

        if (self.regs[REG_DMA_ADDR_HIGH] & 0x80) == 0 {
            src_addr
        } else {
            src_addr & !0x00800000
        }
    }

    pub fn get_dma_count(&mut self) -> i32 {
        (((self.regs[REG_DMA_COUNTER_HIGH] as u32) << 8) | (self.regs[REG_DMA_COUNTER_LOW] as u32)) as i32
    }

    pub fn setup_transfer(&mut self, upper: u16, lower: u16) {
        self.transfer_upper = None;
        self.transfer_type = ((((upper & 0xC000) >> 14) | ((lower & 0x00F0) >> 2))) as u8;
        self.transfer_addr = ((upper & 0x3FFF) | ((lower & 0x0003) << 14)) as u32;
        self.transfer_target = match self.transfer_type & 0x0E {
            0 => TargetType::Vram,
            4 => TargetType::Vsram,
            _ => TargetType::Cram,
        };
        info!("{}: transfer requested of type {:x} ({:?}) to address {:x}", DEV_NAME, self.transfer_type, self.transfer_target, self.transfer_addr);
        if (self.transfer_type & 0x20) != 0 {
            if (self.transfer_type & 0x10) != 0 {
                self.set_dma_mode(DmaType::Copy);
            } else if (self.regs[REG_DMA_ADDR_HIGH] & 0x80) == 0 {
                self.set_dma_mode(DmaType::Memory);
            }
        }
    }

    pub fn get_transfer_target_mut(&mut self) -> &mut [u8] {
        match self.transfer_target {
            TargetType::Vram => &mut self.vram,
            TargetType::Cram => &mut self.cram,
            TargetType::Vsram => &mut self.vsram,
        }
    }

    #[inline(always)]
    fn hsync_int_enabled(&self) -> bool {
        (self.regs[REG_MODE_SET_1] & MODE1_BF_HSYNC_INTERRUPT) != 0
    }

    #[inline(always)]
    fn vsync_int_enabled(&self) -> bool {
        (self.regs[REG_MODE_SET_2] & MODE2_BF_VSYNC_INTERRUPT) != 0
    }

    #[inline(always)]
    fn external_int_enabled(&self) -> bool {
        (self.regs[REG_MODE_SET_3] & MODE3_BF_EXTERNAL_INTERRUPT) != 0
    }

    pub fn get_vram_scroll_a_addr(&self) -> u32 {
        ((self.regs[REG_SCROLL_A_ADDR] as u16) << 10) as u32
    }

    pub fn get_vram_scroll_b_addr(&self) -> u32 {
        ((self.regs[REG_SCROLL_B_ADDR] as u16) << 13) as u32
    }

    pub fn get_vram_window_addr(&self) -> u32 {
        ((self.regs[REG_WINDOW_ADDR] as u16) << 10) as u32
    }

    pub fn get_palette_colour(&self, palette: u8, colour: u8) -> u32 {
        if colour == 0 {
            return 0;
        }
        let rgb = read_beu16(&self.cram[(((palette * 16) + colour) * 2) as usize..]);
        (((rgb & 0xF00) as u32) >> 4) | (((rgb & 0x0F0) as u32) << 8) | (((rgb & 0x00F) as u32) << 20)
    }

    pub fn get_pattern_iter<'a>(&'a self, pattern_name: u16) -> PatternIterator<'a> {
        let pattern_addr = (pattern_name & 0x07FF) << 5;
        let pattern_palette = ((pattern_name & 0x6000) >> 13) as u8;
        let h_rev = (pattern_name & 0x0800) != 0;
        let v_rev = (pattern_name & 0x1000) != 0;
        PatternIterator::new(&self, pattern_addr as u32, pattern_palette, h_rev, v_rev)
    }

    pub fn get_scroll_size(&self) -> (u16, u16) {
        let h = scroll_size(self.regs[REG_SCROLL_SIZE] & 0x03);
        let v = scroll_size((self.regs[REG_SCROLL_SIZE] >> 4) & 0x03);
        (h, v)
    }

    pub fn get_screen_size(&self) -> (u16, u16) {
        let h_cells = if (self.regs[REG_MODE_SET_4] & MODE4_BF_H_CELL_MODE) == 0 { 32 } else { 40 };
        let v_cells = if (self.regs[REG_MODE_SET_2] & MODE2_BF_V_CELL_MODE) == 0 { 28 } else { 30 };
        (h_cells, v_cells)
    }

    pub fn get_window_coords(&self, screen_size: (u16, u16)) -> (u16, u16) {
        let win_h = ((self.regs[REG_WINDOW_H_POS] & 0x1F) << 1) as u16;
        let win_v = (self.regs[REG_WINDOW_V_POS] & 0x1F) as u16;
        let right = (self.regs[REG_WINDOW_H_POS] & 0x80) != 0;
        let down = (self.regs[REG_WINDOW_V_POS] & 0x80) != 0;

        match (right, down) {
            (false, false) => (win_h, win_v),
            (true, false) => (win_h - screen_size.0, win_v),
            (false, true) => (win_h, win_v - screen_size.1),
            (true, true) => (win_h - screen_size.0, win_v - screen_size.1),
        }
    }

    pub fn draw_frame(&mut self, frame: &mut Frame) {
        self.draw_background(frame);
        self.draw_cell_table(frame, self.get_vram_scroll_b_addr());
        self.draw_cell_table(frame, self.get_vram_scroll_a_addr());
        //self.draw_window(frame);
        self.draw_sprites(frame);
    }

    pub fn draw_background(&mut self, frame: &mut Frame) {
        let bg_colour = self.get_palette_colour((self.regs[REG_BACKGROUND] & 0x30) >> 4, self.regs[REG_BACKGROUND] & 0x0f);
        for i in 0..(frame.width as usize * frame.height as usize) {
            frame.bitmap[i] = bg_colour;
        }
    }

    pub fn draw_cell_table(&mut self, frame: &mut Frame, cell_table: u32) {
        let (scroll_h, scroll_v) = self.get_scroll_size();
        let (cells_h, cells_v) = self.get_screen_size();
        let (offset_x, offset_y) = self.get_window_coords((cells_h, cells_v));

        for cell_y in 0..cells_v {
            for cell_x in 0..cells_h {
                let pattern_name = read_beu16(&self.vram[(cell_table + (((cell_x + offset_x) + ((cell_y + offset_y) * scroll_h)) << 1) as u32) as usize..]);
                let iter = self.get_pattern_iter(pattern_name);
                frame.blit((cell_x << 3) as u32, (cell_y << 3) as u32, iter, 8, 8);
            }
        }
    }

    pub fn draw_window(&mut self, frame: &mut Frame) {
        let cell_table = self.get_vram_window_addr();
        let (scroll_h, scroll_v) = self.get_scroll_size();
        let (cells_h, cells_v) = self.get_screen_size();

        for cell_y in 0..cells_v {
            for cell_x in 0..cells_h {
                let pattern_name = read_beu16(&self.vram[(cell_table + ((cell_x + (cell_y * scroll_h)) << 1) as u32) as usize..]);
                let iter = self.get_pattern_iter(pattern_name);
                frame.blit((cell_x << 3) as u32, (cell_y << 3) as u32, iter, 8, 8);
            }
        }
    }

    pub fn build_link_list(&mut self, sprite_table: usize, links: &mut [usize]) -> usize {
        links[0] = 0;
        let mut i = 0;
        loop {
            let link = self.vram[sprite_table + (links[i] * 8) + 3];
            if link == 0 || link > 80 {
                break;
            }
            i += 1;
            links[i] = link as usize;
        }
        i
    }

    pub fn draw_sprites(&mut self, frame: &mut Frame) {
        let sprite_table = (self.regs[REG_SPRITES_ADDR] as usize) << 9;
        let (cells_h, cells_v) = self.get_screen_size();
        let (pos_limit_h, pos_limit_v) = (if cells_h == 32 { 383 } else { 447 }, if cells_v == 28 { 351 } else { 367 });

        let mut links = [0; 80];
        let lowest = self.build_link_list(sprite_table, &mut links);

        for i in (0..lowest + 1).rev() {
            let sprite_data = &self.vram[(sprite_table + (links[i] * 8))..];

            let v_pos = read_beu16(&sprite_data[0..]);
            let size = sprite_data[2];
            let pattern_name = read_beu16(&sprite_data[4..]);
            let h_pos = read_beu16(&sprite_data[6..]);

            let (size_h, size_v) = (((size >> 2) & 0x03) as u16 + 1, (size & 0x03) as u16 + 1);
            let h_rev = (pattern_name & 0x0800) != 0;
            let v_rev = (pattern_name & 0x1000) != 0;
println!("i: {} ({} {}) {:x} ({}, {}) {:x}", i, h_pos, v_pos, size, size_h, size_v, pattern_name);

            for ih in 0..size_h {
                for iv in 0..size_v {
                    let (h, v) = (if !h_rev { ih } else { size_h - ih }, if !v_rev { iv } else { size_v - iv });
                    let (x, y) = (h_pos + h * 8, v_pos + v * 8);
                    if x > 128 && x < pos_limit_h && y > 128 && y < pos_limit_v {
                        let iter = self.get_pattern_iter(((pattern_name & 0x07FF) + (h * size_v) + v) | (pattern_name & 0xF800));

                        println!("{}: ({} {}), {:x}", i, x, y, ((pattern_name & 0x07FF) + (h * size_v) + v));
                        frame.blit(x as u32 - 128, y as u32 - 128, iter, 8, 8);
                    }
                }
            }
        }
    }
}

fn scroll_size(size: u8) -> u16 {
    match size {
        0b00 => 32,
        0b01 => 64,
        0b11 => 128,
        _ => panic!("{}: invalid scroll size option {:x}", DEV_NAME, size),
    }
}

pub struct PatternIterator<'a> {
    state: &'a Ym7101State,
    palette: u8,
    base: usize,
    h_rev: bool,
    v_rev: bool,
    line: i8,
    col: i8,
    second: bool,
}

impl<'a> PatternIterator<'a> {
    pub fn new(state: &'a Ym7101State, start: u32, palette: u8, h_rev: bool, v_rev: bool) -> Self {
        Self {
            state,
            palette,
            base: start as usize,
            h_rev,
            v_rev,
            line: 0,
            col: 0,
            second: false,
        }
    }
}

impl<'a> Iterator for PatternIterator<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.base + (if !self.v_rev { self.line } else { 7 - self.line }) as usize * 4 + (if !self.h_rev { self.col } else { 3 - self.col }) as usize;
        let value = if (!self.h_rev && !self.second) || (self.h_rev && self.second) {
            self.state.get_palette_colour(self.palette, self.state.vram[offset] >> 4)
        } else {
            self.state.get_palette_colour(self.palette, self.state.vram[offset] & 0x0f)
        };

        if !self.second {
            self.second = true;
        } else {
            self.second = false;
            self.col += 1;
            if self.col >= 4 {
                self.col = 0;
                self.line += 1;
            }
        }

        Some(value)
    }
}



pub struct Ym7101 {
    pub swapper: Arc<Mutex<FrameSwapper>>,
    pub state: Ym7101State,
    pub external_interrupt: SyncSignal<bool>,
}

impl Ym7101 {
    pub fn new<H: Host>(host: &mut H, external_interrupt: SyncSignal<bool>) -> Ym7101 {
        let swapper = FrameSwapper::new_shared(320, 224);

        host.add_window(FrameSwapper::to_boxed(swapper.clone())).unwrap();

        Ym7101 {
            swapper,
            state: Ym7101State::new(),
            external_interrupt,
        }
    }
}

impl Transmutable for Ym7101 {
    fn as_addressable(&mut self) -> Option<&mut dyn Addressable> {
        Some(self)
    }

    fn as_steppable(&mut self) -> Option<&mut dyn Steppable> {
        Some(self)
    }
}

impl Steppable for Ym7101 {
    fn step(&mut self, system: &System) -> Result<ClockElapsed, Error> {
        let diff = (system.clock - self.state.last_clock) as u32;
        self.state.last_clock = system.clock;

        if self.state.external_int_enabled() && self.external_interrupt.get() {
            self.external_interrupt.set(false);
            system.get_interrupt_controller().set(true, 2, 26)?;
        }

        self.state.h_clock += diff;
        if (self.state.status & STATUS_IN_HBLANK) == 0 && self.state.v_clock > 58_820 {
            self.state.status |= STATUS_IN_HBLANK;
        }
        if self.state.h_clock > 63_500 {
            self.state.status &= !STATUS_IN_HBLANK;
            self.state.h_clock = 0;
            self.state.h_scanlines = self.state.h_scanlines.wrapping_sub(1);
            if self.state.hsync_int_enabled() && self.state.h_scanlines == 0  {
                self.state.h_scanlines = self.state.regs[REG_H_INTERRUPT];
                system.get_interrupt_controller().set(true, 4, 28)?;
            }
        }

        self.state.v_clock += diff;
        if (self.state.status & STATUS_IN_VBLANK) == 0 && self.state.v_clock > 14_218_000 {
            self.state.status |= STATUS_IN_VBLANK;
        }
        if self.state.v_clock > 16_630_000 {
            self.state.status &= !STATUS_IN_VBLANK;
            self.state.v_clock = 0;
            if self.state.vsync_int_enabled() {
                system.get_interrupt_controller().set(true, 6, 30)?;
            }

            let mut swapper = self.swapper.lock().unwrap();
            self.state.draw_frame(&mut swapper.current);

            //let mut swapper = self.swapper.lock().unwrap();
            //let iter = PatternIterator::new(&self.state, 0x260, 0, true, true);
            //swapper.current.blit(0, 0, iter, 8, 8);

            /*
            // Print Palette
            for i in 0..16 {
                println!("{:x}", self.state.get_palette_colour(0, i));
            }
            */

            /*
            // Print Pattern Table
            let mut swapper = self.swapper.lock().unwrap();
            let (cells_h, cells_v) = self.state.get_screen_size();
            for cell_y in 0..cells_v {
                for cell_x in 0..cells_h {
                    let pattern_addr = (cell_x + (cell_y * cells_h)) * 32;
                    let iter = PatternIterator::new(&self.state, pattern_addr as u32, 0, false, false);
                    swapper.current.blit((cell_x << 3) as u32, (cell_y << 3) as u32, iter, 8, 8);
                }
            }
            */


            /*
            // Print Sprite
            let mut swapper = self.swapper.lock().unwrap();
            self.state.draw_background(&mut swapper.current);
            let sprite_table = (self.state.regs[REG_SPRITES_ADDR] as usize) << 9;
            let (cells_h, cells_v) = self.state.get_screen_size();
            let sprite = 0;
            println!("{:?}", &self.state.vram[(sprite_table + (sprite * 8))..(sprite_table + (sprite * 8) + 8)].iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>());
            let size = self.state.vram[sprite_table + (sprite * 8) + 2];
            let (size_h, size_v) = (((size >> 2) & 0x03) as u16 + 1, (size & 0x03) as u16 + 1);
            let pattern_name = ((self.state.vram[sprite_table + (sprite * 8) + 4] as u16) << 8) | (self.state.vram[sprite_table + (sprite * 8) + 5] as u16);
            let pattern_gen = pattern_name & 0x7FF;
            println!("{:x}", pattern_name);

            for cell_y in 0..size_v {
                for cell_x in 0..size_h {
                    let pattern_addr = (pattern_gen + (cell_y * size_h) + cell_x) as u32;
                    println!("pattern: ({}, {}) {:x}", cell_x, cell_y, pattern_addr);
                    let iter = PatternIterator::new(&self.state, pattern_addr * 32, 3, true, true);
                    swapper.current.blit((cell_x << 3) as u32, (cell_y << 3) as u32, iter, 8, 8);
                }
            }
            */

            //let mut swapper = self.swapper.lock().unwrap();
            //swapper.current.blit(0, 0, PatternIterator::new(&self.state, 0x408 * 32, 3, false, false), 8, 8);
            //swapper.current.blit(0, 8, PatternIterator::new(&self.state, 0x409 * 32, 3, false, false), 8, 8);
            //swapper.current.blit(8, 0, PatternIterator::new(&self.state, 0x402 * 32, 3, false, false), 8, 8);
            //swapper.current.blit(8, 8, PatternIterator::new(&self.state, 0x403 * 32, 3, false, false), 8, 8);
            //swapper.current.blit(16, 0, PatternIterator::new(&self.state, 0x404 * 32, 3, false, false), 8, 8);
            //swapper.current.blit(16, 8, PatternIterator::new(&self.state, 0x405 * 32, 3, false, false), 8, 8);
        }

        if self.state.transfer_run != DmaType::None {
            // TODO we will just do the full dma transfer here, but it really should be stepped

            match self.state.transfer_run {
                DmaType::Memory => {
                    let mut src_addr = self.state.get_dma_src_addr();
                    let mut count = self.state.get_dma_count();

                    info!("{}: starting dma transfer {:x} from Mem:{:x} to {:?}:{:x} ({} bytes)", DEV_NAME, self.state.transfer_type, src_addr, self.state.transfer_target, self.state.transfer_addr, count);
                    let mut bus = system.get_bus();

                    // TODO temporary for debugging, will break at the first cram transfer after the display is on
                    //if (self.state.regs[REG_MODE_SET_2] & 0x40) != 0 && self.state.transfer_target == TargetType::Cram {
                    //   system.get_interrupt_controller().target.as_ref().map(|cpu| cpu.borrow_mut().as_debuggable().unwrap().enable_debugging());
                    //}

                    //bus.dump_memory(src_addr as Address, count as Address);
                    while count > 0 {
                        let mut data = [0; 2];
                        bus.read(src_addr as Address, &mut data)?;

                        {
                            let addr = self.state.transfer_addr;
                            let target = self.state.get_transfer_target_mut();
                            target[addr as usize] = data[0];
                            target[addr as usize + 1] = data[1];
                        }

                        self.state.transfer_addr += self.state.regs[REG_AUTO_INCREMENT] as u32;
                        src_addr += 2;
                        count -= 2;
                    }
                },
                DmaType::Copy => {
                    let mut src_addr = self.state.get_dma_src_addr();
                    let mut count = self.state.get_dma_count();

                    info!("{}: starting dma copy from VRAM:{:x} to VRAM:{:x} ({} bytes)", DEV_NAME, src_addr, self.state.transfer_addr, count);
                    while count > 0 {
                        self.state.vram[self.state.transfer_addr as usize] = self.state.vram[src_addr as usize];
                        self.state.transfer_addr += self.state.regs[REG_AUTO_INCREMENT] as u32;
                        src_addr += 1;
                        count -= 1;
                    }
                },
                DmaType::Fill => {
                    let mut count = self.state.get_dma_count();

                    info!("{}: starting dma fill to VRAM:{:x} ({} bytes) with {:x}", DEV_NAME, self.state.transfer_addr, count, self.state.transfer_fill);
                    while count > 0 {
                        self.state.vram[self.state.transfer_addr as usize] = self.state.transfer_fill as u8;
                        self.state.transfer_addr += self.state.regs[REG_AUTO_INCREMENT] as u32;
                        count -= 1;
                    }
                },
                _ => { warning!("{}: !!! error unexpected transfer mode {:x}", DEV_NAME, self.state.transfer_type); },
            }

            self.state.set_dma_mode(DmaType::None);
        }

        Ok((1_000_000_000 / 13_423_294) * 4)
    }
}

impl Addressable for Ym7101 {
    fn len(&self) -> usize {
        0x20
    }

    fn read(&mut self, addr: Address, data: &mut [u8]) -> Result<(), Error> {
        match addr {
            // Read from Data Port
            0x00 | 0x02 => {
                {
                    let addr = self.state.transfer_addr;
                    let target = self.state.get_transfer_target_mut();
                    for i in 0..data.len() {
                        data[i] = target[addr as usize + i];
                    }
                }
                self.state.transfer_addr += self.state.regs[REG_AUTO_INCREMENT] as u32;
                debug!("{}: data port read {} bytes from {:?}:{:x} returning {:x},{:x}", DEV_NAME, data.len(), self.state.transfer_target, addr, data[0], data[1]);
            },

            // Read from Control Port
            0x04 | 0x06 => {
                debug!("{}: read status byte {:x}", DEV_NAME, self.state.status);
                data[0] = (self.state.status >> 8) as u8;
                data[1] = (self.state.status & 0x00FF) as u8;
            },

            _ => { println!("{}: !!! unhandled read from {:x}", DEV_NAME, addr); },
        }
        Ok(())
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), Error> {
        match addr {
            // Write to Data Port
            0x00 | 0x02 => {
                if (self.state.transfer_type & 0x30) == 0x20 {
                    self.state.transfer_upper = None;
                    self.state.transfer_fill = if data.len() >= 2 { read_beu16(data) } else { data[0] as u16 };
                    self.state.set_dma_mode(DmaType::Fill);
                } else {
                    debug!("{}: data port write {} bytes to {:?}:{:x} with {:?}", DEV_NAME, data.len(), self.state.transfer_target, self.state.transfer_addr, data);

                    {
                        let addr = self.state.transfer_addr as usize;
                        let target = self.state.get_transfer_target_mut();
                        for i in 0..data.len() {
                            target[addr + i] = data[i];
                        }
                    }
                    self.state.transfer_addr += self.state.regs[REG_AUTO_INCREMENT] as u32;
                }
            },

            // Write to Control Port
            0x04 | 0x06 => {
                debug!("{}: write {} bytes to port {:x} with data {:?}", DEV_NAME, data.len(), addr, data);

                let value = read_beu16(data);
                if (value & 0xC000) == 0x8000 {
                    self.state.set_register(value);
                    if data.len() == 4 {
                        let value = read_beu16(&data[2..]);
                        if (value & 0xC000) != 0x8000 {
                            panic!("Unexpected");
                        }
                        self.state.set_register(value);
                    }
                } else {
                    match (data.len(), self.state.transfer_upper) {
                        (2, None) => { self.state.transfer_upper = Some(value) },
                        (2, Some(upper)) => self.state.setup_transfer(upper, read_beu16(data)),
                        (4, None) => self.state.setup_transfer(value, read_beu16(&data[2..])),
                        _ => { error!("{}: !!! error when writing to control port with {} bytes of {:?}", DEV_NAME, data.len(), data); },
                    }
                }
            },

            _ => { warning!("{}: !!! unhandled write to {:x} with {:?}", DEV_NAME, addr, data); },
        }
        Ok(())
    }
}

