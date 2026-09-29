// Windows system tray integration. Gated entirely on Windows:
// macOS expects different lifecycle conventions (LSUIElement plist,
// Cmd+Q never quits, dock icon owns the "show" verb) and Linux tray
// support is fragmented across DEs (GNOME deprecated it without an
// AppIndicator extension, Wayland-pure setups don't have one at all).
// Shipping Windows-first matches the actual user demand from issue
// #18 (koobs on Win11 Pro) and avoids platform-specific bug surface
// we can't reasonably test from CI today.
//
// Architecture: a singleton TrayHandle holds the underlying
// `tray_icon::TrayIcon` and its `MenuItem` references. The iced
// `Subscription` in `subscription.rs` polls the global tray event
// receivers (menu + icon) and converts them into `Message`s the
// dispatcher already understands. The HWND dance for true
// hide-to-tray lives in `dispatch.rs` (it uses `iced::window::run`
// to grab the raw window handle on demand).

#[cfg(target_os = "windows")]
mod imp {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
        Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    /// Menu item ids the dispatcher maps back to `Message`s. The
    /// crate identifies items by their `MenuId` (a string), we keep
    /// the values short and stable so the matching is cheap.
    pub const MENU_ID_SHOW: &str = "oryxis-tray-show";
    pub const MENU_ID_HIDE: &str = "oryxis-tray-hide";
    pub const MENU_ID_QUIT: &str = "oryxis-tray-quit";
    /// Prefix for "active session" submenu entries. The dispatcher
    /// strips the prefix and parses the remainder as a tab index.
    pub const MENU_PREFIX_SESSION: &str = "oryxis-tray-session:";
    /// Prefix for "recent host" entries. Suffix is the connection
    /// UUID (parsed back in dispatch_tabs to open a new tab).
    pub const MENU_PREFIX_HOST: &str = "oryxis-tray-host:";
    /// Prefix for "hidden window" entries (child processes whose
    /// window is currently hidden to the tray). Suffix is the child
    /// PID; the dispatcher forwards a Show command via tray_ipc.
    pub const MENU_PREFIX_HIDDEN: &str = "oryxis-tray-hidden:";

    /// Wrapper that asserts Send + Sync on a value the compiler
    /// thinks is neither. `tray_icon::TrayIcon` contains an Rc /
    /// RefCell which marks it !Send, but we only ever access it
    /// from the main thread (iced's message loop), so the
    /// guarantee holds in practice. The OnceLock storage below
    /// needs the assertion to compile.
    struct ThreadBound<T>(T);
    // SAFETY: see TRAY comment, every read/write happens on the
    // main thread. The unsafe here is a contract with the caller,
    // not a guarantee from the type system.
    unsafe impl<T> Send for ThreadBound<T> {}
    unsafe impl<T> Sync for ThreadBound<T> {}

    /// Held for the lifetime of the process when set. Mutex (not
    /// OnceLock) because the child-promotion path installs the tray
    /// after boot when the original primary dies, and a OnceLock
    /// would refuse the second `set`. iced owns the message loop
    /// the icon's event channels feed into; every interaction
    /// happens from there, hence the ThreadBound safety claim.
    static TRAY: Mutex<Option<ThreadBound<TrayIcon>>> = Mutex::new(None);

    /// `ThreadId` of the thread that called `install()`. Every
    /// subsequent `set_visible` / `rebuild_menu` asserts it's on
    /// the same thread, so a future refactor that moves a tray call
    /// onto a `Task::perform` worker fails loud in debug builds
    /// rather than silently corrupting the `Rc` refcount inside
    /// `tray_icon::TrayIcon`. Release builds skip the assert; the
    /// invariant is documented in the `ThreadBound` SAFETY comment.
    static TRAY_THREAD: std::sync::OnceLock<std::thread::ThreadId> = std::sync::OnceLock::new();

    /// Panic in debug builds if called from a thread other than the
    /// one that installed the tray. No-op once the tray hasn't been
    /// installed yet (still in setup), and no-op in release builds.
    fn assert_tray_thread(op: &'static str) {
        if cfg!(debug_assertions)
            && let Some(expected) = TRAY_THREAD.get()
            && std::thread::current().id() != *expected
        {
            panic!(
                "tray::{op} called from {:?}, expected {:?} (the install thread). \
                 TrayIcon holds non-Send state.",
                std::thread::current().id(),
                expected
            );
        }
    }

    /// Create the tray icon at app startup. Safe to call once; later
    /// calls are no-ops (idempotent via `OnceLock::set`). Returns
    /// `Ok(())` on success or `Err(...)` if the OS refused to
    /// register the icon (rare on Windows, can happen on locked-down
    /// kiosks).
    pub fn install() -> Result<(), Box<dyn std::error::Error>> {
        // Already installed (we're called twice on the same process
        // somehow). Bail without rebuilding.
        if let Ok(guard) = TRAY.lock()
            && guard.is_some()
        {
            return Ok(());
        }
        // Pin the thread that owns the tray. First call wins; later
        // installs after a promotion still happen on the same iced
        // main thread, so the OnceLock pin holds.
        let _ = TRAY_THREAD.set(std::thread::current().id());

        let menu = Menu::new();
        // Labels go through the i18n table so the tray respects the
        // user's language pick (set in Settings -> Interface).
        // Rebuilding the menu on language change is not yet wired:
        // the user has to restart for new labels to land. Same
        // limitation Termius / Tabby ship with on Windows.
        // Bootstrap menu, replaced by rebuild_menu on the first
        // TrayPoll tick after boot. The unified Windows / Active
        // sessions / Recent hosts sections come in via rebuild;
        // here we only carry the always-present Quit entry so the
        // menu has something to render at boot before the first
        // poll. There is no "Show" or "Hide to tray" static item:
        // the user's UX vision (D-lite) routes Show through the
        // Windows section (one row per hidden window) and treats
        // the title-bar minimize / close buttons as the canonical
        // hide path.
        menu.append(&MenuItem::with_id(
            MENU_ID_QUIT,
            crate::i18n::t("tray_quit"),
            true,
            None,
        ))?;

        let icon = load_icon();
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Oryxis")
            .with_icon(icon)
            .build()?;
        // Hide the icon at boot; the dispatcher's visibility rule
        // mounts it as soon as the primary's own window OR any child
        // reports hidden state. tray-icon's builder doesn't expose a
        // with_visible(false), so we toggle right after build.
        let _ = tray.set_visible(false);

        // Promotion path may have raced us; if a TRAY is already
        // here when we try to install, drop ours (the existing one
        // wins) so we never end up with two icons in the tray.
        if let Ok(mut guard) = TRAY.lock()
            && guard.is_none()
        {
            *guard = Some(ThreadBound(tray));
        }
        Ok(())
    }

    fn load_icon() -> Icon {
        let bytes = include_bytes!("../../../resources/logo_64.png");
        let img = image::load_from_memory(bytes)
            .expect("bundled tray icon decodes")
            .into_rgba8();
        let (w, h) = img.dimensions();
        Icon::from_rgba(img.into_raw(), w, h).expect("rgba dimensions match")
    }

    /// Drain any pending menu click event without blocking. Called
    /// from the iced subscription poll. Returns the clicked menu
    /// item's id, or `None` when the queue is empty.
    pub fn poll_menu_event() -> Option<String> {
        MenuEvent::receiver().try_recv().ok().map(|e| e.id.0)
    }

    /// Toggle the tray icon's visibility in the notification area.
    /// The user-visible rule lives in the dispatcher (primary's own
    /// window hidden OR any child reports hidden -> show icon, else
    /// hide). This helper just forwards to tray-icon's set_visible.
    /// Failure is logged + swallowed; the worst case is a stale tray
    /// icon hanging around for a tick longer than ideal.
    pub fn set_visible(visible: bool) {
        assert_tray_thread("set_visible");
        let Ok(guard) = TRAY.lock() else { return };
        let Some(ThreadBound(tray)) = guard.as_ref() else { return };
        if let Err(e) = tray.set_visible(visible) {
            tracing::warn!("tray set_visible({visible}): {e}");
        }
    }

    /// Replace the tray icon's menu with a freshly built one that
    /// reflects the current `Active sessions` and `Recent hosts`
    /// lists. Idempotent: the tray-icon crate swaps the underlying
    /// HMENU in place, the OS picks up the new menu on the next
    /// right-click (open menus aren't disrupted because Windows
    /// uses a snapshot).
    ///
    /// The two parameters are pre-formatted (label, id-suffix)
    /// pairs so this module doesn't need to know about TerminalTab
    /// / Connection internals. The caller assembles them from app
    /// state and decides the cap (top N).
    pub fn rebuild_menu(
        active_sessions: &[(String, String)],
        recent_hosts: &[(String, String)],
        hidden_windows: &[(String, String)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_tray_thread("rebuild_menu");
        let guard = match TRAY.lock() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        };
        let Some(ThreadBound(tray)) = guard.as_ref() else {
            // No tray installed (install() failed or platform stub),
            // nothing to rebuild. Caller doesn't care.
            return Ok(());
        };

        let menu = Menu::new();
        // Unified "Windows" section: every hidden window the user
        // owns lives here (primary's own as the first row when
        // primary is hidden, then every child via the IPC registry).
        // Clicking any row surfaces THAT window. Per the user's
        // UX vision the menu doesn't carry a redundant "Hide to
        // tray" entry; the window's own title-bar minimize / close
        // are the canonical hide path.
        //
        // The caller passes `hidden_windows` already merged (primary
        // first if it belongs there, then children). The id-suffix
        // is the owning process's PID; the dispatcher checks for
        // self_pid to decide between a local TrayShow and an IPC
        // send to a child.
        if !hidden_windows.is_empty() {
            menu.append(&MenuItem::new(
                crate::i18n::t("tray_windows"),
                false,
                None,
            ))?;
            for (label, id_suffix) in hidden_windows {
                let id = format!("{MENU_PREFIX_HIDDEN}{id_suffix}");
                menu.append(&MenuItem::with_id(id, label, true, None))?;
            }
        }

        if !active_sessions.is_empty() {
            if !hidden_windows.is_empty() {
                menu.append(&PredefinedMenuItem::separator())?;
            }
            // Header item, disabled so it reads as a section label.
            menu.append(&MenuItem::new(
                crate::i18n::t("tray_active_sessions"),
                false,
                None,
            ))?;
            for (label, id_suffix) in active_sessions {
                let id = format!("{MENU_PREFIX_SESSION}{id_suffix}");
                menu.append(&MenuItem::with_id(id, label, true, None))?;
            }
        }

        if !recent_hosts.is_empty() {
            menu.append(&PredefinedMenuItem::separator())?;
            menu.append(&MenuItem::new(
                crate::i18n::t("tray_recent_hosts"),
                false,
                None,
            ))?;
            for (label, id_suffix) in recent_hosts {
                let id = format!("{MENU_PREFIX_HOST}{id_suffix}");
                menu.append(&MenuItem::with_id(id, label, true, None))?;
            }
        }

        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&MenuItem::with_id(
            MENU_ID_QUIT,
            crate::i18n::t("tray_quit"),
            true,
            None,
        ))?;

        tray.set_menu(Some(Box::new(menu)));
        Ok(())
    }

    /// Drain any pending icon click event (left click, right click,
    /// double click). Returned variant lets the dispatcher decide
    /// the verb. Empty queue -> `None`.
    pub fn poll_icon_event() -> Option<TrayIconEvent> {
        TrayIconEvent::receiver().try_recv().ok()
    }

    /// Try to acquire the single-instance mutex. Returns true if
    /// we won (we ARE primary), false if another instance owns it.
    /// Side effect: when we win, the handle stays alive for the
    /// rest of the process via a deliberate leak so we hold the
    /// mutex until exit.
    ///
    /// Called twice in the lifecycle:
    /// 1. At boot, to decide primary vs child role.
    /// 2. Periodically from children's TrayPoll to detect a dead
    ///    primary and promote (the OS releases mutexes when the
    ///    owning process exits, so a fresh CreateMutexW succeeds
    ///    again once primary is gone).
    pub fn try_acquire_mutex() -> bool {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, GetLastError,
        };
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name: Vec<u16> = "Local\\oryxis-single-instance\0"
            .encode_utf16()
            .collect();
        let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        if already {
            unsafe {
                CloseHandle(h);
            }
            return false;
        }
        // Leak the handle so the mutex object stays owned for the
        // lifetime of this process. The OS reclaims it on exit.
        true
    }

    /// Back-compat wrapper kept for `main.rs`. Returns the inverse
    /// of `try_acquire_mutex`: true when another instance is
    /// already running. The original API was the negation; this
    /// shim avoids churning the call site for what is essentially
    /// the same call.
    pub fn another_instance_running() -> bool {
        !try_acquire_mutex()
    }

    /// Hide the window passed in, going through the raw HWND
    /// instead of `winit::Window::set_visible` (iced 0.14 doesn't
    /// expose it). Called from the iced dispatcher inside a
    /// `iced::window::run` callback, which guarantees we're on the
    /// UI thread with a valid handle. Returns `false` if the handle
    /// wasn't the expected `Win32WindowHandle` variant; that
    /// shouldn't happen in practice but we'd rather log + skip than
    /// panic.
    ///
    /// Takes `&dyn iced::Window` so the dispatcher
    /// can pass the exact closure argument from `window::run`
    /// without an extra crate import. `Window` is `HasWindowHandle
    /// + HasDisplayHandle`, which is the trait method we need.
    pub fn hide_window(handle: &dyn iced::Window) -> bool {
        use iced::window::raw_window_handle::RawWindowHandle;
        use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};

        let Ok(wh) = handle.window_handle() else {
            return false;
        };
        let RawWindowHandle::Win32(win32) = wh.as_raw() else {
            return false;
        };
        // SAFETY: HWND is valid for the lifetime of the &dyn handle
        // reference; SW_HIDE is a constant integer argument with no
        // pointer semantics. The call is documented as thread-safe
        // for the owning thread, which is where iced::window::run
        // dispatches us.
        unsafe {
            let _ = ShowWindow(win32.hwnd.get() as _, SW_HIDE);
        }
        true
    }

    /// Live mirror of the `minimize_to_tray` setting, readable from
    /// the Win32 subclass proc below. The proc runs inside the window
    /// procedure and can't borrow app state, so the setting is pushed
    /// here from `boot` and from the settings toggle instead.
    static MINIMIZE_TO_TRAY: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Set by the subclass proc when it swallowed a native minimize
    /// and hid the window. Drained by the tray heartbeat so the app
    /// can sync `is_window_hidden` + the IPC registry, the same
    /// bookkeeping `handle_window_minimize` does on the button path.
    static NATIVE_HIDE_PENDING: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// One-shot guard: the heartbeat retries until the subclass lands,
    /// then stops.
    static HOOK_INSTALLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Gates WM_DROPFILES parsing so normal-integrity windows keep their
    /// original OLE-only behavior and never interpret an unsolicited
    /// message as an HDROP handle.
    static ELEVATED_DROP_ENABLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Paths received through the classic Shell drop protocol while
    /// this process is elevated. The Win32 subclass cannot dispatch an
    /// iced message directly, so the tray heartbeat drains this queue.
    static ELEVATED_FILE_DROPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Push the current `minimize_to_tray` setting down to the
    /// subclass proc. Call on boot and on every toggle, otherwise the
    /// proc keeps deciding on a stale value.
    pub fn set_minimize_to_tray(on: bool) {
        MINIMIZE_TO_TRAY.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// True exactly once after the subclass proc hid the window on a
    /// native minimize verb.
    pub fn take_native_hide() -> bool {
        NATIVE_HIDE_PENDING.swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// Drain paths delivered by the elevated-process drag fallback.
    /// Each path re-enters the normal SFTP/terminal drop dispatcher so
    /// sidebar routing, batching and progress UI stay single-sourced.
    pub fn take_elevated_file_drops() -> Vec<PathBuf> {
        ELEVATED_FILE_DROPS
            .lock()
            .map(|mut paths| std::mem::take(&mut *paths))
            .unwrap_or_default()
    }

    /// Whether the subclass is already in place. Lets the caller stop
    /// spawning an install task on every heartbeat once it landed.
    pub fn minimize_hook_installed() -> bool {
        HOOK_INSTALLED.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Install the Win32 subclass that handles native minimize and the
    /// elevated-process file-drop fallback. In a normal process winit's
    /// OLE drop target remains untouched; in an elevated process UIPI
    /// blocks that OLE path from a normal Explorer, so we switch this
    /// window to the classic Shell `WM_DROPFILES` protocol instead.
    ///
    /// The button path routes through `Message::Tabs(TabsMessage::WindowMinimize)`, but
    /// nothing generates that message for a native minimize: winit
    /// reports the state change after the fact and iced has no
    /// `minimize_requests()` to mirror `close_requests()`. Swallowing
    /// the message before `DefWindowProc` is also what avoids a
    /// visible minimize-then-vanish flicker: reacting to a completed
    /// minimize would play the animation first.
    ///
    /// Returns false when the window handle isn't a Win32 one or the
    /// subclass call fails; the caller retries on the next tick.
    pub fn install_minimize_hook(handle: &dyn iced::Window) -> bool {
        use iced::window::raw_window_handle::RawWindowHandle;
        use windows_sys::Win32::UI::Shell::SetWindowSubclass;

        if HOOK_INSTALLED.load(std::sync::atomic::Ordering::Relaxed) {
            return true;
        }
        let Ok(wh) = handle.window_handle() else {
            return false;
        };
        let RawWindowHandle::Win32(win32) = wh.as_raw() else {
            return false;
        };
        // SAFETY: the HWND is valid for the lifetime of the &dyn
        // handle reference, and SetWindowSubclass must run on the
        // thread that owns the window, which is where
        // `iced::window::run` dispatches us. The subclass id (1) is
        // ours to pick and only has to be unique per (window, proc)
        // pair; the reference data is unused. The subclass chains
        // ahead of winit's own window procedure rather than replacing
        // it, so everything we don't claim still reaches winit via
        // DefSubclassProc.
        let ok = unsafe {
            SetWindowSubclass(win32.hwnd.get() as _, Some(minimize_subclass_proc), 1, 0) != 0
        };
        if ok {
            HOOK_INSTALLED.store(true, std::sync::atomic::Ordering::Relaxed);
            match process_is_elevated() {
                Ok(true) => enable_elevated_file_drops(win32.hwnd.get() as _),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    "could not detect elevation for drag-and-drop fallback: {error}"
                ),
            }
        }
        ok
    }

    fn process_is_elevated() -> std::io::Result<bool> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                std::ptr::addr_of_mut!(elevation).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            let error = (ok == 0).then(std::io::Error::last_os_error);
            CloseHandle(token);
            match error {
                Some(error) => Err(error),
                None => Ok(elevation.TokenIsElevated != 0),
            }
        }
    }

    fn enable_elevated_file_drops(hwnd: windows_sys::Win32::Foundation::HWND) {
        use windows_sys::Win32::System::Ole::RevokeDragDrop;
        use windows_sys::Win32::UI::Shell::DragAcceptFiles;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            ChangeWindowMessageFilterEx, MSGFLT_ALLOW, WM_COPYDATA, WM_DROPFILES,
        };

        // winit registered an OLE IDropTarget when the window was made.
        // Explorer prefers that target and never falls back to WM_DROPFILES,
        // so revoke it only for the elevated compatibility path.
        unsafe {
            let _ = RevokeDragDrop(hwnd);
        }

        // WM_COPYGLOBALDATA (0x0049) carries the cross-integrity global
        // memory block used by the Shell. It is intentionally not a public
        // Win32 constant, but is part of the established WM_DROPFILES UIPI
        // compatibility sequence. Keep the filter narrow and per-window.
        const WM_COPYGLOBALDATA: u32 = 0x0049;
        for message in [WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA] {
            let ok = unsafe {
                ChangeWindowMessageFilterEx(
                    hwnd,
                    message,
                    MSGFLT_ALLOW,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                tracing::warn!(
                    "could not allow elevated drag message 0x{message:04X}: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        unsafe {
            DragAcceptFiles(hwnd, 1);
        }
        ELEVATED_DROP_ENABLED.store(true, std::sync::atomic::Ordering::Release);
        tracing::info!("enabled elevated Explorer file-drop compatibility");
    }

    /// The subclass procedure installed by `install_minimize_hook`.
    unsafe extern "system" fn minimize_subclass_proc(
        hwnd: windows_sys::Win32::Foundation::HWND,
        msg: u32,
        wparam: windows_sys::Win32::Foundation::WPARAM,
        lparam: windows_sys::Win32::Foundation::LPARAM,
        _subclass_id: usize,
        _ref_data: usize,
    ) -> windows_sys::Win32::Foundation::LRESULT {
        use windows_sys::Win32::UI::Shell::DefSubclassProc;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            ShowWindow, SC_MINIMIZE, SW_HIDE, WM_DROPFILES, WM_SYSCOMMAND,
        };

        if msg == WM_DROPFILES
            && ELEVATED_DROP_ENABLED.load(std::sync::atomic::Ordering::Acquire)
        {
            receive_elevated_file_drop(wparam as _);
            return 0;
        }

        // The low 4 bits of wParam are reserved for the system on
        // WM_SYSCOMMAND (Windows uses them internally for accelerator
        // / mnemonic state), so the command has to be masked out
        // before comparing.
        if msg == WM_SYSCOMMAND
            && (wparam & 0xFFF0) == SC_MINIMIZE as usize
            && MINIMIZE_TO_TRAY.load(std::sync::atomic::Ordering::Relaxed)
        {
            // SAFETY: hwnd comes from the window procedure itself, so
            // it is live and owned by this thread. SW_HIDE is a plain
            // integer constant.
            unsafe {
                let _ = ShowWindow(hwnd, SW_HIDE);
            }
            NATIVE_HIDE_PENDING.store(true, std::sync::atomic::Ordering::Relaxed);
            // Deliberately NOT calling `set_visible` here, even though
            // this runs on the tray's own thread and the icon is what
            // brings the window back. It goes through Shell_NotifyIcon,
            // a synchronous call into explorer that can block for
            // seconds when the shell is busy, and this stack is a
            // WM_SYSCOMMAND dispatch: stalling it would freeze the
            // minimize itself. The heartbeat drains the flag instead,
            // so the icon can trail the hide by up to one tick. The
            // chrome-button path has no such constraint and reveals it
            // in the same frame.
            // Claim the message: returning 0 without chaining is what
            // keeps the window from actually minimizing.
            return 0;
        }
        // SAFETY: plain forward of the original arguments to the next
        // procedure in the subclass chain.
        unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
    }

    fn receive_elevated_file_drop(hdrop: windows_sys::Win32::UI::Shell::HDROP) {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::UI::Shell::{DragFinish, DragQueryFileW};

        let count = unsafe { DragQueryFileW(hdrop, u32::MAX, std::ptr::null_mut(), 0) };
        let mut dropped = Vec::with_capacity(count as usize);
        for index in 0..count {
            let len = unsafe { DragQueryFileW(hdrop, index, std::ptr::null_mut(), 0) };
            if len == 0 {
                continue;
            }
            let mut buffer = vec![0u16; len as usize + 1];
            let written = unsafe {
                DragQueryFileW(hdrop, index, buffer.as_mut_ptr(), buffer.len() as u32)
            };
            if written != 0 {
                dropped.push(PathBuf::from(OsString::from_wide(
                    &buffer[..written as usize],
                )));
            }
        }
        unsafe {
            DragFinish(hdrop);
        }
        if !dropped.is_empty()
            && let Ok(mut pending) = ELEVATED_FILE_DROPS.lock()
        {
            pending.extend(dropped);
        }
    }

    /// Restore a hidden window: show it, then pull to foreground.
    /// `SW_SHOW` alone leaves it in the previous z-order, so an
    /// `SetForegroundWindow` chases it to land on top. If the
    /// window was minimized when hidden, `SW_RESTORE` instead of
    /// `SW_SHOW` un-minimizes too.
    pub fn show_window(handle: &dyn iced::Window) -> bool {
        use iced::window::raw_window_handle::RawWindowHandle;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SetForegroundWindow, ShowWindow, SW_RESTORE,
        };

        let Ok(wh) = handle.window_handle() else {
            return false;
        };
        let RawWindowHandle::Win32(win32) = wh.as_raw() else {
            return false;
        };
        // SAFETY: same rationale as hide_window. SetForegroundWindow
        // can fail silently (Windows focus-stealing prevention) but
        // doesn't unsafe-misuse the HWND on failure.
        unsafe {
            let hwnd = win32.hwnd.get() as _;
            let _ = ShowWindow(hwnd, SW_RESTORE);
            let _ = SetForegroundWindow(hwnd);
        }
        true
    }
}

#[cfg(target_os = "windows")]
pub use imp::*;

/// Cross-platform stubs so call sites compile uniformly. On non-
/// Windows targets the tray module is a no-op: `install` succeeds
/// silently, polls return `None`. The settings UI also hides the
/// tray-related toggles outside Windows, but the runtime hooks stay
/// callable to keep dispatch.rs free of cfg branches.
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
mod stub {
    pub const MENU_ID_SHOW: &str = "oryxis-tray-show";
    pub const MENU_ID_HIDE: &str = "oryxis-tray-hide";
    pub const MENU_ID_QUIT: &str = "oryxis-tray-quit";
    pub const MENU_PREFIX_SESSION: &str = "oryxis-tray-session:";
    pub const MENU_PREFIX_HOST: &str = "oryxis-tray-host:";
    pub const MENU_PREFIX_HIDDEN: &str = "oryxis-tray-hidden:";

    pub fn rebuild_menu(
        _active_sessions: &[(String, String)],
        _recent_hosts: &[(String, String)],
        _hidden_windows: &[(String, String)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn install() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn set_visible(_visible: bool) {}

    /// Stub: never reports a duplicate instance on non-Windows.
    /// macOS / Linux apps can still be launched twice; the limitation
    /// matches the platform-only scope of the tray feature itself.
    pub fn another_instance_running() -> bool {
        false
    }

    /// Stub: always reports success on non-Windows, so the
    /// promotion path treats every process as already-primary
    /// (matches the no-tray scope).
    pub fn try_acquire_mutex() -> bool {
        true
    }

    pub fn poll_menu_event() -> Option<String> {
        None
    }

    /// Placeholder type so subscription.rs can match a single shape
    /// regardless of platform. The Windows path returns the real
    /// `tray_icon::TrayIconEvent`; here we never produce one.
    pub enum TrayIconEvent {}

    pub fn poll_icon_event() -> Option<TrayIconEvent> {
        None
    }

    /// Stub: never actually hides anything on non-Windows targets.
    /// Same signature as the Windows impl so dispatch.rs stays cfg-
    /// free. Returns false so the caller knows nothing happened.
    pub fn hide_window(_handle: &dyn iced::Window) -> bool {
        false
    }

    /// Stub: never actually shows anything on non-Windows targets.
    pub fn show_window(_handle: &dyn iced::Window) -> bool {
        false
    }

    /// Stub: the native-minimize interception is a Win32 window
    /// subclass, so there is nothing to mirror here. Non-Windows
    /// targets keep the plain OS minimize.
    pub fn set_minimize_to_tray(_on: bool) {}

    /// Stub: no subclass, so a native minimize is never swallowed.
    pub fn take_native_hide() -> bool {
        false
    }

    /// Stub: the cross-integrity WM_DROPFILES fallback is Windows-only.
    pub fn take_elevated_file_drops() -> Vec<std::path::PathBuf> {
        Vec::new()
    }

    /// Stub: reports success so the caller stops retrying.
    pub fn install_minimize_hook(_handle: &dyn iced::Window) -> bool {
        true
    }

    /// Stub: reports installed so the caller never spawns the task.
    pub fn minimize_hook_installed() -> bool {
        true
    }
}

#[cfg(not(target_os = "windows"))]
pub use stub::*;
