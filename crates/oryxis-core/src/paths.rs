//! Central resolution of the app's `~/.oryxis` data directory.
//!
//! `ORYXIS_HOME` overrides the home directory the `.oryxis` tree lives
//! under. It exists for the harness sandbox on Windows, where
//! `dirs::home_dir()` is `SHGetKnownFolderPath` (a WinAPI call that
//! ignores `$HOME` / `%USERPROFILE%`). A file named `oryxis.portable`
//! beside the executable is the user-facing portable mode: the marker's
//! directory becomes the home, so the whole tree sits beside the app.
//! Child binaries installed inside that tree find the same marker by
//! walking their executable's ancestors. Both mechanisms deliberately
//! govern only the app's own data tree: user files outside it
//! (`~/.ssh/config`, `~/.aws`, `~/.Xauthority`, the OS download folder)
//! keep resolving against the real OS home, so a portable vault never
//! relocates the user's own configuration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Marker beside a portable installation's main executable.
pub const PORTABLE_MARKER: &str = "oryxis.portable";

/// The home directory the `.oryxis` tree lives under: the `ORYXIS_HOME`
/// override when set and non-empty, the directory carrying the portable
/// marker next, and the OS home otherwise.
pub fn home_dir() -> Option<PathBuf> {
    resolve_home(
        std::env::var_os("ORYXIS_HOME"),
        portable_home(),
        dirs::home_dir(),
    )
}

/// The `~/.oryxis` data directory itself (vault, plugin cache, fonts,
/// logs, tray runtime, agent socket). Not created here; each consumer
/// creates what it needs on demand.
pub fn oryxis_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".oryxis"))
}

/// Pure core of [`home_dir`], split out so the resolution is
/// unit-testable without mutating the process environment (`set_var` is
/// unsafe under Rust 2024, and test binaries run their tests on
/// parallel threads).
fn resolve_home(
    override_home: Option<OsString>,
    portable_home: Option<PathBuf>,
    os_home: Option<PathBuf>,
) -> Option<PathBuf> {
    override_home
        // An empty export must fall through to the real home, matching
        // `dirs_sys`' own `HOME` handling; otherwise the data dir would
        // land in `./.oryxis` under the process working directory.
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or(portable_home)
        .or(os_home)
}

/// Locate the nearest portable marker above the running executable.
/// The ancestor walk lets helper binaries under
/// `.oryxis/bin/` or `.oryxis/plugins/...` resolve the same root as the
/// main executable instead of creating a nested data tree of their own.
fn portable_home() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    portable_home_from_exe(&exe)
}

fn portable_home_from_exe(exe: &Path) -> Option<PathBuf> {
    exe.parent()?
        .ancestors()
        .find(|dir| dir.join(PORTABLE_MARKER).is_file())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ORYXIS_HOME` overrides the data directory's home. The harness
    /// sandbox depends on this on Windows, where `dirs::home_dir()` is
    /// a WinAPI call that ignores `$HOME` / `%USERPROFILE%`: without
    /// the override a harness run would read and write the REAL
    /// profile's `.oryxis`. Exercised through the pure resolver; the
    /// end-to-end pin lives in `oryxis-vault/tests/oryxis_home.rs`, a
    /// binary with exactly one test and therefore no `getenv` race.
    #[test]
    fn oryxis_home_overrides_home_dir() {
        let sandbox = || Some(OsString::from("/sandbox"));
        let portable = || Some(PathBuf::from("/portable"));
        let home = || Some(PathBuf::from("/real-home"));
        // The environment override wins over portable and OS homes.
        assert_eq!(
            resolve_home(sandbox(), portable(), home()),
            Some(PathBuf::from("/sandbox"))
        );
        // Without an override, the explicit portable install wins.
        assert_eq!(resolve_home(None, portable(), home()), portable());
        // No portable marker: the OS home.
        assert_eq!(resolve_home(None, None, home()), home());
        // An accidental `export ORYXIS_HOME=` falls through to the real
        // resolution chain instead of landing the data dir in the
        // working directory.
        assert_eq!(
            resolve_home(Some(OsString::new()), portable(), home()),
            portable()
        );
        // Nothing resolves at all: consumers surface their own errors.
        assert_eq!(resolve_home(Some(OsString::new()), None, None), None);
    }

    #[test]
    fn portable_marker_is_found_above_nested_helper_binary() {
        let root = std::env::temp_dir().join(format!(
            "oryxis-portable-path-test-{}",
            uuid::Uuid::new_v4()
        ));
        let helper = root
            .join(".oryxis")
            .join("plugins")
            .join("mcp")
            .join("1.0")
            .join("oryxis-mcp.exe");
        std::fs::create_dir_all(helper.parent().unwrap()).unwrap();
        std::fs::write(root.join(PORTABLE_MARKER), b"portable\n").unwrap();

        assert_eq!(portable_home_from_exe(&helper), Some(root.clone()));

        std::fs::remove_dir_all(root).unwrap();
    }
}
