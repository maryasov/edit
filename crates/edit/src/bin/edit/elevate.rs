// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Saving files the current user lacks write permission for.
//!
//! When a save fails with "permission denied" on Unix, the buffer is staged
//! into a temporary file and an elevated helper (`sudo` or `doas`) copies it
//! over the target. The TUI is suspended for the duration, so the helper can
//! prompt for a password directly on the terminal. The password is handled
//! by `sudo`/`doas` itself and never enters this process.

use std::path::{Path, PathBuf};

use edit::tui::Context;

use crate::apperr;
use crate::state::{State, error_log_add};

/// True when the elevated save flow is available on this platform.
pub const SUPPORTED: bool = cfg!(unix);

/// Routes a failed save into the elevated save flow, if applicable.
///
/// Permission errors are deferred to the main loop (`State::elevated_save`),
/// because `draw()` must not touch the terminal and the elevated save has to
/// suspend the TUI for `sudo` to prompt for a password. Everything else lands
/// in the error log, as before.
pub fn handle_save_error(
    ctx: &mut Context,
    state: &mut State,
    err: apperr::Error,
    target: PathBuf,
) {
    if SUPPORTED && is_permission_denied(&err) && !target.as_os_str().is_empty() {
        state.elevated_save = Some(target);
        ctx.needs_rerender();
    } else {
        error_log_add(ctx, state, err);
    }
}

/// Performs the elevated save of the active document to `target`.
/// No-op on platforms without the flow (Windows keeps the plain error).
pub fn save_elevated(state: &mut State, target: &Path) -> apperr::Result<()> {
    let was_dirty = state.documents.active().is_some_and(|doc| doc.buffer.borrow().is_dirty());
    elevated_save(state, target, was_dirty)
}

#[cfg(unix)]
fn is_permission_denied(err: &apperr::Error) -> bool {
    matches!(err, apperr::Error::Io(err) if err.kind() == std::io::ErrorKind::PermissionDenied)
}

#[cfg(not(unix))]
fn is_permission_denied(_err: &apperr::Error) -> bool {
    false
}

#[cfg(not(unix))]
fn elevated_save(_state: &mut State, _target: &Path, _was_dirty: bool) -> apperr::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn elevated_save(state: &mut State, target: &Path, was_dirty: bool) -> apperr::Result<()> {
    use edit::sys;

    let staged = stage_buffer(state)?;
    let result = copy_elevated(&staged, target);
    // Delete the staging file, whatever happened. It may contain
    // sensitive data and sits in a shared temporary directory.
    let _ = std::fs::remove_file(&staged);

    match result {
        Ok(()) => {
            // Adopt the target's new file identity, like a regular save does.
            if let Some(doc) = state.documents.active_mut()
                && let Ok(id) = sys::file_id(None, target)
            {
                doc.file_id = Some(id);
            }
            Ok(())
        }
        Err(err) => {
            // `write_file` marked the buffer as clean, but the elevated
            // copy failed: restore the dirtiness the user left behind.
            if was_dirty && let Some(doc) = state.documents.active_mut() {
                doc.buffer.borrow_mut().mark_as_dirty();
            }
            Err(err)
        }
    }
}

/// Writes the active document's contents into a private temporary file,
/// so that an elevated process can copy it over the inaccessible target.
#[cfg(unix)]
fn stage_buffer(state: &mut State) -> apperr::Result<PathBuf> {
    use std::env;
    use std::fs::OpenOptions;
    use std::io;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::process::id;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::localization::{LocId, loc};

    let Some(doc) = state.documents.active_mut() else {
        return Err(io::Error::other(loc(LocId::ElevatedSaveNoDocument)).into());
    };

    // `create_new` (O_EXCL) is essential: a predictable name in a shared
    // temp directory would otherwise follow symlinks planted by others.
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let dir = env::temp_dir();
    let mut staged = None;
    for attempt in 0..32u32 {
        let candidate = dir.join(format!("msedit-elevate-{}-{}-{}", id(), nanos, attempt));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&candidate) {
            Ok(_) => {
                staged = Some(candidate);
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    let Some(path) = staged else {
        return Err(io::Error::other(loc(LocId::ElevatedSaveStagingFailed)).into());
    };

    let mut file = OpenOptions::new().write(true).open(&path)?;
    {
        let mut tb = doc.buffer.borrow_mut();
        // Note: this marks the buffer as clean; `elevated_save` undoes
        // that if the elevated copy ends up failing.
        tb.write_file(&mut file)?;
    }

    Ok(path)
}

/// Suspends the TUI, runs the elevated copy, and resumes the TUI.
#[cfg(unix)]
fn copy_elevated(source: &std::path::Path, target: &std::path::Path) -> apperr::Result<()> {
    use edit::sys;

    use crate::localization::{LocId, loc};

    // Leave the alternate screen and hand the terminal back its original
    // (cooked) mode, so the helper can prompt for a password on the TTY.
    sys::write_stdout(concat!(
        "\x1b[?1002;1006;2004l", // mouse tracking + bracketed paste off
        "\x1b[0 q\x1b[?25h",     // default cursor style, cursor visible
        "\x1b[?1049l",           // leave the alternate screen
    ));
    sys::restore_modes_for_child();

    let path = target.to_string_lossy();
    let line = loc(LocId::ElevatedSaveNotWritable).replace("{path}", &path);
    sys::write_stdout(&format!("\n{line}\n{}\n", loc(LocId::ElevatedSavePasswordPrompt)));

    let result = run_helper(source, target);

    // A blank line, so the helper's output doesn't glue to the redrawn UI.
    sys::write_stdout("\n");

    // Resume the TUI: raw mode, alternate screen, input modes back on.
    sys::switch_modes()?;
    sys::write_stdout("\x1b[?1049h\x1b[?1002;1006;2004h");

    result
}

/// Copies `source` over `target` via `sudo` (or `doas`).
///
/// Ctrl+C at the password prompt must abort the helper, not the editor:
/// the parent ignores SIGINT/SIGQUIT while the child waits, and the child
/// resets them to their default (ignored dispositions survive exec).
#[cfg(unix)]
fn run_helper(source: &std::path::Path, target: &std::path::Path) -> apperr::Result<()> {
    use std::io;
    use std::os::unix::process::CommandExt as _;

    use crate::localization::{LocId, loc};

    let mut command = helper_command(source, target)?;
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }

    let prev_int = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    let prev_quit = unsafe { libc::signal(libc::SIGQUIT, libc::SIG_IGN) };
    let status = command.status();
    unsafe {
        libc::signal(libc::SIGINT, prev_int);
        libc::signal(libc::SIGQUIT, prev_quit);
    }

    let status = status?;
    if !status.success() {
        let err = match status.code() {
            Some(code) => io::Error::other(format!("{} ({code})", loc(LocId::ElevatedSaveFailed))),
            None => io::Error::other(loc(LocId::ElevatedSaveFailed)),
        };
        return Err(err.into());
    }
    Ok(())
}

/// Builds the helper command, probing for `sudo` and then `doas`.
#[cfg(unix)]
fn helper_command(
    source: &std::path::Path,
    target: &std::path::Path,
) -> std::io::Result<std::process::Command> {
    use std::io;
    use std::process::Command;

    use crate::localization::{LocId, loc};

    for program in ["sudo", "doas"] {
        if !command_exists(program) {
            continue;
        }
        let mut command = Command::new(program);
        // `cp` keeps the target's ownership and permissions when
        // overwriting it, which is what we want for system files.
        command.arg("cp").arg(source).arg(target);
        return Ok(command);
    }
    Err(io::Error::other(loc(LocId::ElevatedSaveNoHelper)))
}

/// Checks whether `program` exists as an executable file in `PATH`.
#[cfg(unix)]
fn command_exists(program: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    use std::{env, fs};

    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        fs::metadata(&candidate)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    })
}
