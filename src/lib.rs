#![no_std]
#![no_main]
#![feature(lang_items, alloc)]

extern crate alloc;

mod instruction;
mod syscall;

type Pubkey = [u8; 32];

use alloc::vec::Vec;
use core::{
    alloc::Layout,
    mem::size_of,
    ptr::null_mut,
    slice::{from_raw_parts, from_raw_parts_mut},
};

const SUCCESS: u64 = 0;
const NON_DUP_MARKER: u8 = u8::MAX;
const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;
const BPF_ALIGN_OF_U128: usize = 8;
/// Start address of the memory region used for program heap.
const HEAP_START_ADDRESS: u64 = 0x300000000;
/// Length of the heap memory region used for program heap.
pub const HEAP_LENGTH: usize = 32 * 1024;

#[repr(u64)]
enum AccountType<'a> {
    Signer(Account<'a>),
    MutableSigner(MutableAccount<'a>),
    Account(Account<'a>),
    Writable(MutableAccount<'a>),
    Program(&'a Pubkey),
    WritableDup(u8),
}

struct Account<'a> {
    id: &'a Pubkey,
    lamport: u64,
    data: &'a [u8],
}

struct MutableAccount<'a> {
    id: &'a Pubkey,
    lamport: &'a mut u64,
    data: &'a mut [u8],
}

#[no_mangle]
pub  extern "C" fn entrypoint(input: *mut u8) -> u64 {
    log(b"Calling test");
    // compute input length

    let mut offset: usize = 0;
    let num_accounts = unsafe {
        *(input.add(offset) as *const u64)
    }  as usize;
    offset += size_of::<u64>();

    let mut accounts: Vec<AccountType> = Vec::with_capacity(num_accounts);

    for _ in 0..num_accounts {
        let dup_info = unsafe {*(input.add(offset) as *const u8)};
        offset += size_of::<u32>();

        let original_data_len_offset = offset;
        offset += size_of::<u32>();

        if dup_info == NON_DUP_MARKER {
            // key + owner + lamport
            offset += size_of::<Pubkey>() + size_of::<Pubkey>() + size_of::<u64>();

            let data_len = unsafe {*(input.add(offset) as *const u64) as usize};
            offset += size_of::<u64>();

            // Store the original data length for detecting invalid reallocations and
            // requires that MAX_PERMITTED_DATA_LENGTH fits in a u32
            unsafe {
                *(input.add(original_data_len_offset) as *mut u32) = data_len as u32;
            }

            //let data = from_raw_parts_mut(input.add(offset), data_len);
            offset += data_len + MAX_PERMITTED_DATA_INCREASE;
            offset += (offset as *const u8).align_offset(BPF_ALIGN_OF_U128); // padding

            // rent epoch
            offset += size_of::<u64>();
        }
    }

    let accounts = unsafe { from_raw_parts(input, offset) };

    let instruction_data_len = unsafe {*(input.add(offset) as *const u64) as usize};
    offset += size_of::<u64>();

    let instruction_data = unsafe { from_raw_parts(input.add(offset), instruction_data_len) };
    offset += instruction_data_len;

    // Program Id
    let program_id: &Pubkey = unsafe {&*(input.add(offset) as *const Pubkey) };

    SUCCESS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let msg = b"Panic";
    //syscall::sol_log_(msg.as_ptr(), msg.len() as u64);
    loop {}
}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

/// The bump allocator used as the default rust heap when running programs.
pub struct BumpAllocator {
    pub start: usize,
    pub len: usize,
}
/// Integer arithmetic in this global allocator implementation is safe when
/// operating on the prescribed `HEAP_START_ADDRESS` and `HEAP_LENGTH`. Any
/// other use may overflow and is thus unsupported and at one's own risk.
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pos_ptr = self.start as *mut usize;

        let mut pos = *pos_ptr;
        if pos == 0 {
            // First time, set starting position
            pos = self.start + self.len;
        }
        pos = pos.saturating_sub(layout.size());
        pos &= !(layout.align().wrapping_sub(1));
        if pos < self.start + size_of::<*mut u8>() {
            return null_mut();
        }
        *pos_ptr = pos;
        pos as *mut u8
    }
    #[inline]
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        // I'm a bump allocator, I don't free
    }
}

#[global_allocator]
static A: BumpAllocator = BumpAllocator {
    start: HEAP_START_ADDRESS as usize,
    len: HEAP_LENGTH,
};

fn log(msg: &[u8]) {
    unsafe {
        syscall::sol_log_(msg.as_ptr(), msg.len() as u64);
        syscall::sol_log_data(msg.as_ptr(), msg.len() as u64);
    }
}
