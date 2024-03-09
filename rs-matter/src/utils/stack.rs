// This global variable tracks the highest point of the stack
thread_local!(pub static STACK_START: core::cell::Cell<usize> = core::cell::Cell::new(usize::MAX));

#[macro_export]
macro_rules! stack_ptr {
    () => ({
        use core::arch::asm;

        // Grab a copy of the stack pointer
        let x: usize;
        unsafe {
            asm!("mov {}, rsp", out(reg) x);
        }
        x
    })
}

#[macro_export]
macro_rules! stack_start {
    () => {{
        $crate::utils::stack::STACK_START.set($crate::stack_ptr!());
    }};
}

#[macro_export]
macro_rules! stack_usage {
    () => {{
        $crate::utils::stack::STACK_START.get() - $crate::stack_ptr!()
    }};
}

#[macro_export]
macro_rules! log_stack_usage {
    () => {{
        log::error!(
            "[{}({})] STACK USAGE: {}",
            file!(),
            line!(),
            $crate::stack_usage!()
        );
    }};
}
