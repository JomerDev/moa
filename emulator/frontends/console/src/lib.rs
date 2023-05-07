
use moa_core::Error;
use moa_core::host::{Host, Tty, ControllerEvent, Audio, DummyAudio, FrameReceiver, EventSender};

pub struct ConsoleFrontend;

impl Host for ConsoleFrontend {
    fn add_pty(&self) -> Result<Box<dyn Tty>, Error> {
        use moa_common::tty::SimplePty;
        Ok(Box::new(SimplePty::open()?))
    }

    fn add_video_source(&mut self, _receiver: FrameReceiver) -> Result<(), Error> {
        println!("console: add_window() is not supported from the console; ignoring request...");
        Ok(())
    }

    fn register_controllers(&mut self, _sender: EventSender<ControllerEvent>) -> Result<(), Error> {
        println!("console: register_controller() is not supported from the console; ignoring request...");
        Ok(())
    }

    fn add_audio_source(&mut self) -> Result<Box<dyn Audio>, Error> {
        println!("console: create_audio_source() is not supported from the console; returning dummy device...");
        Ok(Box::new(DummyAudio()))
    }
}

