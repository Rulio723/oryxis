//! Windows taskbar JumpList: the recent-hosts menu that appears when the
//! user right-clicks the Oryxis taskbar button. Each entry relaunches
//! `oryxis.exe --connect <uuid>`, which the single-instance IPC routes
//! into the running window (or a fresh one).
//!
//! # AppUserModelID and the "no harm" choice
//!
//! A JumpList is filed under an AppUserModelID (AUMID) and only shows on a
//! taskbar button that carries the same AUMID. The installer reserves
//! `io.oryxis.Oryxis` for this (see `resources/installer.nsi`) but does not
//! yet stamp it on the Start-menu shortcut. Rather than call
//! `SetCurrentProcessExplicitAppUserModelID` (a process-wide switch other
//! shell surfaces key off of), we tag only the *window* with the AUMID via
//! `SHGetPropertyStoreForWindow` and file the list under the same string
//! with `SetAppID`. That gives the running window's button a working
//! JumpList without touching the process AUMID. Toast notifications carry
//! the same id explicitly (`util.rs::toast_app_id`, backed by an HKCU
//! `AppUserModelId` registration), so all three surfaces agree on
//! `io.oryxis.Oryxis` with zero process-global state.
//!
//! Known limitation (owner-tracked in the installer): a pinned-but-not-
//! running Start-menu shortcut keeps its implicit exe-path AUMID until the
//! installer stamps the `.lnk`, so its JumpList only lights up once the app
//! is running. Not new harm; documented.
//!
//! Everything here is best-effort: every failure is swallowed, so a
//! missing shell interface or an uninstalled/portable build simply yields
//! no JumpList rather than an error. Windows only; a no-op stub elsewhere.

#[cfg(target_os = "windows")]
pub(crate) const AUMID: &str = "io.oryxis.Oryxis";

/// Tag the app window with our AUMID so its taskbar button adopts the same
/// identity the JumpList is filed under. Call once, from inside an
/// `iced::window::run` callback (main / UI thread) so the raw handle is
/// valid. No-op off Windows.
#[cfg(target_os = "windows")]
pub(crate) fn tag_window(handle: &dyn iced::Window) {
    // Packaged (MSIX) processes get their AUMID from the package
    // identity; retagging the window detaches the taskbar button from
    // it, which breaks JumpList and toast routing at once.
    if crate::packaged::is_packaged() {
        return;
    }

    use iced::window::raw_window_handle::RawWindowHandle;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::UI::Shell::PropertiesSystem::{
        IPropertyStore, SHGetPropertyStoreForWindow,
    };

    let Ok(wh) = handle.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32) = wh.as_raw() else {
        return;
    };
    let hwnd = HWND(win32.hwnd.get() as *mut core::ffi::c_void);

    let result: windows::core::Result<()> = (|| unsafe {
        let store: IPropertyStore = SHGetPropertyStoreForWindow(hwnd)?;
        // An explicit window AUMID changes how Explorer resolves the
        // taskbar group's identity.  In particular, a portable build has
        // no Start-menu shortcut carrying this AUMID for Explorer to fall
        // back to, so setting only PKEY_AppUserModel_ID leaves the button
        // with the generic application glyph.  Microsoft requires the
        // relaunch properties to be written BEFORE the ID (setting the ID
        // tells the taskbar to refresh the window immediately).
        //
        // Point both relaunch and icon resolution at the running binary,
        // not an install directory: this keeps copied/USB builds portable.
        // winresource embeds logo.ico as numeric resource 1; the standard
        // resource syntax uses a negative numeric resource id.
        let exe = std::env::current_exe().map_err(windows::core::Error::from)?;
        let exe_path = exe.to_string_lossy();
        let relaunch_command = format!("\"{exe_path}\"");
        let relaunch_icon = format!("{exe_path},-1");
        let command = PROPVARIANT::from(relaunch_command.as_str());
        store.SetValue(&imp::PKEY_APPUSERMODEL_RELAUNCH_COMMAND, &command)?;
        let display_name = PROPVARIANT::from("Oryxis");
        store.SetValue(
            &imp::PKEY_APPUSERMODEL_RELAUNCH_DISPLAY_NAME_RESOURCE,
            &display_name,
        )?;
        let icon = PROPVARIANT::from(relaunch_icon.as_str());
        store.SetValue(&imp::PKEY_APPUSERMODEL_RELAUNCH_ICON_RESOURCE, &icon)?;

        // `From<&str>` builds a BSTR-backed PROPVARIANT, which the property
        // system accepts for these string-valued keys.
        let value = PROPVARIANT::from(AUMID);
        store.SetValue(&imp::PKEY_APPUSERMODEL_ID, &value)?;
        store.Commit()?;
        Ok(())
    })();
    if let Err(e) = result {
        tracing::debug!("jumplist: window AUMID tag failed: {e}");
    }
}

/// Rebuild the "recent hosts" JumpList category. `entries` is the ordered
/// (label, connection-id) list, most-recent first; `category` is the
/// localized heading. Call on the main thread (COM is STA-initialized by
/// winit there). No-op off Windows.
#[cfg(target_os = "windows")]
pub(crate) fn set_recent(exe: &std::path::Path, category: &str, entries: &[(String, uuid::Uuid)]) {
    if let Err(e) = imp::build(exe, category, entries) {
        tracing::debug!("jumplist: rebuild failed: {e}");
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use std::collections::HashSet;

    use windows::Win32::Foundation::PROPERTYKEY;
    use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
    use windows::Win32::UI::Shell::Common::{IObjectArray, IObjectCollection};
    use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
    use windows::Win32::UI::Shell::{
        DestinationList, EnumerableObjectCollection, ICustomDestinationList, IShellLinkW, ShellLink,
    };
    use windows::core::{GUID, HSTRING, Interface};

    /// `PKEY_Title` ({F29F85E0-4FF9-1068-AB91-08002B27B3D9}, pid 2): the
    /// visible label of a JumpList row (SetDescription is only the tooltip).
    const PKEY_TITLE: PROPERTYKEY = PROPERTYKEY {
        fmtid: GUID::from_u128(0xF29F85E0_4FF9_1068_AB91_08002B27B3D9),
        pid: 2,
    };

    /// `PKEY_AppUserModel_ID` ({9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3},
    /// pid 5): the window/shortcut AUMID property.
    pub(super) const PKEY_APPUSERMODEL_RELAUNCH_COMMAND: PROPERTYKEY = PROPERTYKEY {
        fmtid: GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3),
        pid: 2,
    };

    pub(super) const PKEY_APPUSERMODEL_RELAUNCH_ICON_RESOURCE: PROPERTYKEY = PROPERTYKEY {
        fmtid: GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3),
        pid: 3,
    };

    pub(super) const PKEY_APPUSERMODEL_RELAUNCH_DISPLAY_NAME_RESOURCE: PROPERTYKEY = PROPERTYKEY {
        fmtid: GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3),
        pid: 4,
    };

    pub(super) const PKEY_APPUSERMODEL_ID: PROPERTYKEY = PROPERTYKEY {
        fmtid: GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3),
        pid: 5,
    };

    /// Collect the connection ids the user explicitly removed from a prior
    /// JumpList (returned by `BeginList`). We must not re-add these, per the
    /// destination-list contract, or the removed row springs back.
    fn removed_ids(removed: &IObjectArray) -> HashSet<uuid::Uuid> {
        let mut out = HashSet::new();
        let count = unsafe { removed.GetCount() }.unwrap_or(0);
        for i in 0..count {
            let Ok(link) = (unsafe { removed.GetAt::<IShellLinkW>(i) }) else {
                continue;
            };
            // Recover the id from the link's `--connect <uuid>` arguments.
            let mut buf = [0u16; 512];
            if unsafe { link.GetArguments(&mut buf) }.is_ok() {
                let s = String::from_utf16_lossy(&buf);
                if let Some(id) = s.trim_end_matches('\0').rsplit(' ').next()
                    && let Ok(uuid) = uuid::Uuid::parse_str(id)
                {
                    out.insert(uuid);
                }
            }
        }
        out
    }

    pub(super) fn build(
        exe: &std::path::Path,
        category: &str,
        entries: &[(String, uuid::Uuid)],
    ) -> windows::core::Result<()> {
        let exe_h = HSTRING::from(exe.as_os_str());

        unsafe {
            let list: ICustomDestinationList =
                CoCreateInstance(&DestinationList, None, CLSCTX_INPROC_SERVER)?;
            // An MSIX process already carries the package AUMID
            // (`<PackageFamilyName>!<App Id>`), which is what its taskbar
            // button is filed under. Overriding it with our own string
            // would file the list under an id no button carries, so it
            // would silently never appear; without the call the list
            // inherits the process identity and works.
            if !crate::packaged::is_packaged() {
                list.SetAppID(&HSTRING::from(super::AUMID))?;
            }

            let mut max_slots: u32 = 0;
            let removed: IObjectArray = list.BeginList(&mut max_slots)?;
            let skip = removed_ids(&removed);

            let collection: IObjectCollection =
                CoCreateInstance(&EnumerableObjectCollection, None, CLSCTX_INPROC_SERVER)?;

            let mut added = 0u32;
            for (label, id) in entries {
                if added >= max_slots {
                    break;
                }
                if skip.contains(id) {
                    continue;
                }
                let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
                link.SetPath(&exe_h)?;
                link.SetArguments(&HSTRING::from(format!("--connect {id}")))?;
                // Use the exe's own icon for each entry.
                link.SetIconLocation(&exe_h, 0)?;

                let store: IPropertyStore = link.cast()?;
                let title = PROPVARIANT::from(label.as_str());
                store.SetValue(&PKEY_TITLE, &title)?;
                store.Commit()?;

                collection.AddObject(&link)?;
                added += 1;
            }

            if added > 0 {
                let array: IObjectArray = collection.cast()?;
                list.AppendCategory(&HSTRING::from(category), &array)?;
            }
            // Commit even with zero entries so a previously-populated list
            // is cleared when the user has no recent hosts left.
            list.CommitList()?;
        }
        Ok(())
    }
}

// ---- Non-Windows no-op stubs (keep call sites platform-free) -------------

#[cfg(not(target_os = "windows"))]
pub(crate) fn tag_window(_handle: &dyn iced::Window) {}

#[cfg(not(target_os = "windows"))]
pub(crate) fn set_recent(
    _exe: &std::path::Path,
    _category: &str,
    _entries: &[(String, uuid::Uuid)],
) {
}
