use std::ffi::{CStr, CString};
use std::ptr::NonNull;
use std::sync::Mutex;

use tracing::{debug, trace};

use super::{FirewallError, NftRunner};

#[allow(warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/libnftables_bindings.rs"));
}

trait NftApi {
    type Handle: Copy;

    fn new_context(&self) -> Option<Self::Handle>;
    fn free_context(&self, handle: Self::Handle);
    fn buffer_output(&self, handle: Self::Handle) -> i32;
    fn buffer_error(&self, handle: Self::Handle) -> i32;
    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32;
    fn error_output(&self, handle: Self::Handle) -> Option<String>;
}

#[derive(Debug, Clone, Copy)]
struct RealNftApi;

impl NftApi for RealNftApi {
    type Handle = NonNull<bindings::nft_ctx>;

    fn new_context(&self) -> Option<Self::Handle> {
        // SAFETY: `nft_ctx_new` is an FFI constructor that returns either null or a valid
        // pointer to an allocated context when passed a valid flags value.
        let pointer = unsafe { bindings::nft_ctx_new(bindings::NFT_CTX_DEFAULT) };
        NonNull::new(pointer)
    }

    fn free_context(&self, handle: Self::Handle) {
        // SAFETY: `handle` comes from `nft_ctx_new` and is freed exactly once in `Drop`.
        unsafe { bindings::nft_ctx_free(handle.as_ptr()) };
    }

    fn buffer_output(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_output(handle.as_ptr()) }
    }

    fn buffer_error(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_error(handle.as_ptr()) }
    }

    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32 {
        // SAFETY: both pointers are valid for the duration of this call.
        unsafe { bindings::nft_run_cmd_from_buffer(handle.as_ptr(), script.as_ptr()) }
    }

    fn error_output(&self, handle: Self::Handle) -> Option<String> {
        // SAFETY: pointer is owned by libnftables for this context and may be null.
        let pointer = unsafe { bindings::nft_ctx_get_error_buffer(handle.as_ptr()) };
        if pointer.is_null() {
            return None;
        }

        // SAFETY: non-null C string pointer returned by libnftables.
        let cstr = unsafe { CStr::from_ptr(pointer) };
        Some(cstr.to_string_lossy().trim().to_string())
    }
}

struct NftContext<A>
where
    A: NftApi,
{
    api: A,
    handle: A::Handle,
}

impl<A> NftContext<A>
where
    A: NftApi,
{
    fn new(api: A) -> Result<Self, FirewallError> {
        let Some(handle) = api.new_context() else {
            return Err(FirewallError::LibContextCreate);
        };

        let output_rc = api.buffer_output(handle);
        if output_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: output_rc,
            });
        }

        let error_rc = api.buffer_error(handle);
        if error_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "error",
                code: error_rc,
            });
        }

        Ok(Self { api, handle })
    }

    fn run_script(&mut self, script: &str) -> Result<(), FirewallError> {
        let c_script = CString::new(script).map_err(|_| FirewallError::ScriptContainsNul)?;
        let result = self.api.run_script(self.handle, &c_script);
        if result == 0 {
            return Ok(());
        }

        let stderr = self
            .api
            .error_output(self.handle)
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| "unknown libnftables error".to_string());

        Err(FirewallError::LibCommandFailure {
            code: result,
            stderr,
        })
    }
}

impl<A> Drop for NftContext<A>
where
    A: NftApi,
{
    fn drop(&mut self) {
        self.api.free_context(self.handle);
    }
}

pub struct LibNftablesRunner {
    context: Mutex<NftContext<RealNftApi>>,
}

impl LibNftablesRunner {
    pub fn new() -> Result<Self, FirewallError> {
        let context = NftContext::new(RealNftApi)?;
        Ok(Self {
            context: Mutex::new(context),
        })
    }
}

impl NftRunner for LibNftablesRunner {
    fn run_commands(&self, commands: &[String]) -> Result<(), FirewallError> {
        let script = format!("{}\n", commands.join("\n"));
        trace!(script = %script, "executing nft script via libnftables");
        for command in commands {
            // Log libnftables execution in CLI-equivalent format for operator visibility.
            debug!(program = "nft", command = %command, "executing firewall command");
        }
        let mut guard = self
            .context
            .lock()
            .map_err(|_| FirewallError::LibContextLock)?;
        let result = guard.run_script(&script);
        if result.is_ok() {
            trace!("nft libnftables script executed successfully");
            return Ok(());
        }

        if let Err(FirewallError::LibCommandFailure { code, stderr }) = &result {
            debug!(code = *code, stderr = %stderr, "nft libnftables script execution failed");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug)]
    struct MockState {
        next_context: Option<usize>,
        output_rc: i32,
        error_rc: i32,
        run_rc: i32,
        error_message: String,
        freed: usize,
        scripts: Vec<String>,
    }

    #[derive(Clone)]
    struct MockApi {
        state: Arc<Mutex<MockState>>,
    }

    impl MockApi {
        fn new(state: MockState) -> Self {
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn state(&self) -> MockState {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.clone()
        }
    }

    impl NftApi for MockApi {
        type Handle = usize;

        fn new_context(&self) -> Option<Self::Handle> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.next_context
        }

        fn free_context(&self, _handle: Self::Handle) {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.freed += 1;
        }

        fn buffer_output(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.output_rc
        }

        fn buffer_error(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.error_rc
        }

        fn run_script(&self, _handle: Self::Handle, script: &CStr) -> i32 {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.scripts.push(script.to_string_lossy().to_string());
            guard.run_rc
        }

        fn error_output(&self, _handle: Self::Handle) -> Option<String> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            Some(guard.error_message.clone())
        }
    }

    fn base_state() -> MockState {
        MockState {
            next_context: Some(1),
            output_rc: 0,
            error_rc: 0,
            run_rc: 0,
            error_message: String::new(),
            freed: 0,
            scripts: Vec::new(),
        }
    }

    #[test]
    fn wrapper_runs_script_successfully() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api.clone()) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("add table inet portcullis");
        assert!(result.is_ok());

        let state = api.state();
        assert_eq!(state.scripts.len(), 1);
    }

    #[test]
    fn wrapper_reports_script_failure() {
        let mut state = base_state();
        state.run_rc = -1;
        state.error_message = "syntax error".to_string();
        let api = MockApi::new(state);
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("invalid");
        assert!(matches!(
            result,
            Err(FirewallError::LibCommandFailure { code: -1, .. })
        ));
    }

    #[test]
    fn wrapper_rejects_nul_byte_scripts() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("bad\0script");
        assert!(matches!(result, Err(FirewallError::ScriptContainsNul)));
    }

    #[test]
    fn wrapper_frees_context_on_drop() {
        let api = MockApi::new(base_state());
        {
            let context = match NftContext::new(api.clone()) {
                Ok(value) => value,
                Err(error) => panic!("expected context creation to succeed: {error}"),
            };
            let _ = context;
        }

        let state = api.state();
        assert_eq!(state.freed, 1);
    }

    #[test]
    fn wrapper_fails_when_context_creation_fails() {
        let mut state = base_state();
        state.next_context = None;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(result, Err(FirewallError::LibContextCreate)));
    }

    #[test]
    fn wrapper_fails_when_output_buffering_fails() {
        let mut state = base_state();
        state.output_rc = -1;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(
            result,
            Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: -1
            })
        ));
    }
}
