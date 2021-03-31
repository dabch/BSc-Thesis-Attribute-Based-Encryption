// taken from https://opus4.kobv.de/opus4-haw/frontdoor/deliver/index/docId/786/file/I000819827Thesis.pdf

use core::ptr;
pub struct StackChecker;
impl StackChecker {
    pub fn paint() {
        extern "C" {
            static mut _stack_start: u32;
            static mut _stack_end: u32;
        }
        unsafe {
            let mut stack_start: *mut u32; // Get current stack pointer
            asm!("MOV {}, SP", out(reg_thumb) stack_start); // Add buffer for the following call stack
            stack_start = stack_start.offset(-0xc);
            let count = stack_start as usize - &_stack_end as *const u32 as usize;
            ptr::write_bytes(&mut _stack_end as *mut u32 as *mut u8, 0xAB, count);
        }
    }
    pub fn get() -> usize {
        extern "C" {
            static mut _stack_start: u32;
            static mut _stack_end: u32;
        }
        let mut stack_size = 0;
        let mut following_patterns = 0;
        unsafe {
            let mut cur_ptr = &_stack_end as *const u32 as *mut u32;
            cur_ptr = cur_ptr.offset(0x1);
            while cur_ptr < &_stack_start as *const u32 as *mut u32 {
                if *cur_ptr != 0xABABABAB {
                    return &_stack_end as *const u32 as *mut u32 as usize - cur_ptr as usize;
                } 
                cur_ptr = cur_ptr.offset(0x1);
            }
            // let mut cur_ptr = &_stack_start as *const u32 as *mut u32;
            // cur_ptr = cur_ptr.offset(-0x1);
            // while cur_ptr > &_stack_end as *const u32 as *mut u32 {
            //     if *cur_ptr == 0xABABABAB {
            //         following_patterns += 1;
            //     } else {
            //         following_patterns = 0;
            //     }
            //     if following_patterns == 1 {
            //         let stack_start_addr = &_stack_start as *const u32 as usize;
            //         stack_size = stack_start_addr - cur_ptr.offset(0x1) as usize;
            //     }
            //     cur_ptr = cur_ptr.offset(-0x1);
            // }
        }
        1
    }
}
