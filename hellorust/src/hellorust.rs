#![no_std]
#![feature(lang_items)]
#![feature(intrinsics)]

#[lang="sized"]

#[link(name = "c")]
extern {
	fn puts(s: *const u8);
}

#[start]
fn start(_argc: int, _argv: *const *const u8) -> int {
	let s = "Hello  Rust!\0"; // &str
    unsafe {
    	let (s,_): (*const u8, uint) = transmute(s); // see core::raw::Slice
    	puts(s);
    }
	return 0;
}

#[lang = "stack_exhausted"] extern fn stack_exhausted() {}
#[lang = "eh_personality"] extern fn eh_personality() {}

extern "rust-intrinsic" {
    fn transmute<T, U>(x: T) -> U;
}


