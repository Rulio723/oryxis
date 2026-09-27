//! Interop tests against the reference lrzsz `sz` / `rz` binaries.
//!
//! These are the real synthetic integration tests for ZMODEM: the
//! crate's own loopback drives our sender against our receiver (both
//! `zmodem2`), which proves the driving logic but NOT wire-compat with
//! the tool people actually run over SSH. Here we spawn the genuine
//! `sz` (it sends -> we download) and `rz` (it receives -> we upload),
//! wire their stdio to our driver's channels exactly as the app wires a
//! live session, and assert a byte-exact round trip.
//!
//! Skipped (with a printed note, not a failure) when lrzsz isn't
//! installed, so dev machines and Windows pass; the Linux CI installs
//! `lrzsz` so they actually run there.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use oryxis_zmodem::{
    DEFAULT_STREAMING_WINDOW, Direction, Progress, TransferIo, TransferSpec, run,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

/// True when `bin` can be executed (found on PATH). `-h` is enough to
/// tell "installed" from "missing"; we ignore the exit status.
fn tool_available(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("-h")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// A private scratch dir under the system temp, unique per test.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("oryxis-lrzsz-{}-{tag}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// A deterministic payload with the bytes ZMODEM must escape (XON 0x11,
/// XOFF 0x13, ZDLE 0x18, CR 0x0d) sprinkled through it, big enough to
/// span many subpackets.
fn payload() -> Vec<u8> {
    (0..64 * 1024u32).map(|i| (i % 251) as u8).collect()
}

/// Pump `reader` (a child's stdout) into an unbounded channel until EOF.
fn spawn_reader<R>(mut reader: R, tx: mpsc::UnboundedSender<Vec<u8>>)
where
    R: AsyncReadExt + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Pump a channel into `writer` (a child's stdin) until it closes.
fn spawn_writer<W>(mut writer: W, mut rx: mpsc::UnboundedReceiver<Vec<u8>>)
where
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if writer.write_all(&b).await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_from_real_sz() {
    if !tool_available("sz") {
        eprintln!("SKIP download_from_real_sz: `sz` (lrzsz) not installed");
        return;
    }
    let dir = scratch("dl");
    let src = dir.join("payload.bin");
    let dest_dir = dir.join("incoming");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let data = payload();
    std::fs::write(&src, &data).unwrap();

    // The real sender: `sz -b` (binary) streams the file over stdout and
    // reads our protocol replies from stdin.
    let mut child = Command::new("sz")
        .arg("-b")
        .arg(&src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx); // sz stdout -> our receiver
    spawn_writer(child_in, wire_out_rx); // our replies -> sz stdin

    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: Arc::new(AtomicBool::new(false)),
    };
    let driver = tokio::spawn(run(
        Direction::Download,
        TransferSpec::Download {
            budget: None,
            dest_dir: dest_dir.clone(),
            resume_owner: None,
        },
        Vec::new(),
        io,
    ));

    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("download deadlocked")
        .unwrap();

    let mut completed = false;
    while let Ok(p) = progress_rx.try_recv() {
        match p {
            Progress::Completed { trailing } => {
                completed = true;
                // sz's "OO" sign-off is protocol, not terminal output:
                // the driver must have absorbed it.
                assert!(trailing.is_empty(), "unexpected trailing bytes: {trailing:?}");
            }
            Progress::Error(e) => panic!("download error: {e}"),
            _ => {}
        }
    }
    assert!(completed, "receiver never reported Completed");
    let got = std::fs::read(dest_dir.join("payload.bin")).expect("downloaded file");
    assert_eq!(got, data, "downloaded bytes differ from what sz sent");

    // Issue #77 regression: sz must exit promptly. A stranded ZFIN
    // reply leaves it retrying against silence for ~20 s (holding the
    // user's tty), which this generous bound still rejects.
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("sz did not exit promptly after session end (ZFIN reply not flushed?)")
        .expect("sz wait failed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_multiple_files_from_real_sz() {
    if !tool_available("sz") {
        eprintln!("SKIP download_multiple_files_from_real_sz: `sz` not installed");
        return;
    }
    let dir = scratch("dl-multi");
    let dest_dir = dir.join("incoming");
    std::fs::create_dir_all(&dest_dir).unwrap();
    // Three distinct payloads, including an empty file, sent in one
    // batch: exercises FileStarted/FileCompleted repeating before
    // SessionCompleted (a single-file test can't catch a loop that
    // stops after the first file).
    let files = [
        ("a.bin", payload()),
        ("empty.bin", Vec::new()),
        ("b.bin", (0..4096u32).map(|i| (i % 97) as u8).collect::<Vec<_>>()),
    ];
    let mut cmd = Command::new("sz");
    cmd.arg("-b");
    for (name, data) in &files {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        cmd.arg(&p);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx);
    spawn_writer(child_in, wire_out_rx);

    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: Arc::new(AtomicBool::new(false)),
    };
    let driver = tokio::spawn(run(
        Direction::Download,
        TransferSpec::Download {
            budget: None,
            dest_dir: dest_dir.clone(),
            resume_owner: None,
        },
        Vec::new(),
        io,
    ));
    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("multi-file download deadlocked")
        .unwrap();

    let mut completed = false;
    while let Ok(p) = progress_rx.try_recv() {
        if let Progress::Error(e) = p {
            panic!("download error: {e}");
        }
        if matches!(p, Progress::Completed { .. }) {
            completed = true;
        }
    }
    assert!(completed, "never completed");
    for (name, data) in &files {
        let got = std::fs::read(dest_dir.join(name)).unwrap_or_else(|_| panic!("missing {name}"));
        assert_eq!(&got, data, "{name} bytes differ");
    }
    // Same issue #77 regression bound as the single-file test.
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("sz did not exit promptly after session end (ZFIN reply not flushed?)")
        .expect("sz wait failed");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Interrupted download resume: a leftover `.oryxis-part` holding the
/// first half of the file makes the receiver answer ZFILE with
/// ZRPOS(half), and `sz` sends only the rest. The pre-created half
/// carries DIFFERENT bytes than the source: if the driver actually
/// resumed, the final file keeps our bytes in the first half (a
/// from-zero transfer would equal the source exactly), which proves
/// append-at-offset rather than rewrite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_resumes_from_a_partial() {
    if !tool_available("sz") {
        eprintln!("SKIP download_resumes_from_a_partial: `sz` not installed");
        return;
    }
    let dir = scratch("resume");
    let dest_dir = dir.join("incoming");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let src = dir.join("big.bin");
    let data = payload();
    std::fs::write(&src, &data).unwrap();
    let half = data.len() / 2;
    let marker = vec![0xABu8; half];
    let part = dest_dir.join(format!("big.bin{}", oryxis_zmodem::PART_SUFFIX));
    std::fs::write(&part, &marker).unwrap();

    let mut child = Command::new("sz")
        .arg("-b")
        .arg(&src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx);
    spawn_writer(child_in, wire_out_rx);

    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: Arc::new(AtomicBool::new(false)),
    };
    let driver = tokio::spawn(run(
        Direction::Download,
        TransferSpec::Download {
            budget: None,
            dest_dir: dest_dir.clone(),
            resume_owner: None,
        },
        Vec::new(),
        io,
    ));
    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("resumed download deadlocked")
        .unwrap();

    let mut completed = false;
    while let Ok(p) = progress_rx.try_recv() {
        match p {
            Progress::Completed { .. } => completed = true,
            Progress::Error(e) => panic!("download error: {e}"),
            _ => {}
        }
    }
    assert!(completed, "resumed download never completed");

    let got = std::fs::read(dest_dir.join("big.bin")).expect("final file");
    assert_eq!(got.len(), data.len());
    assert_eq!(&got[..half], &marker[..], "first half rewritten: did not resume");
    assert_eq!(&got[half..], &data[half..], "second half differs");
    assert!(
        !std::fs::exists(&part).unwrap_or(false),
        "part file left behind after finalize"
    );
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("sz did not exit promptly after resumed session")
        .expect("sz wait failed");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `sz -e` (escape all control bytes) opens with ZSINIT and blocks
/// until the receiver acknowledges it; a receiver that ignores the
/// frame stalls the whole session into sz's timeouts (the pre-fix
/// behavior). The prompt-exit bound is the regression assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_from_sz_with_control_escaping() {
    if !tool_available("sz") {
        eprintln!("SKIP download_from_sz_with_control_escaping: `sz` not installed");
        return;
    }
    let dir = scratch("szesc");
    let src = dir.join("payload.bin");
    let dest_dir = dir.join("incoming");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let data = payload();
    std::fs::write(&src, &data).unwrap();

    let mut child = Command::new("sz")
        .arg("-b")
        .arg("-e")
        .arg(&src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx);
    spawn_writer(child_in, wire_out_rx);

    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: Arc::new(AtomicBool::new(false)),
    };
    let driver = tokio::spawn(run(
        Direction::Download,
        TransferSpec::Download {
            budget: None,
            dest_dir: dest_dir.clone(),
            resume_owner: None,
        },
        Vec::new(),
        io,
    ));
    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("sz -e download deadlocked")
        .unwrap();

    let mut completed = false;
    while let Ok(p) = progress_rx.try_recv() {
        match p {
            Progress::Completed { .. } => completed = true,
            Progress::Error(e) => panic!("download error: {e}"),
            _ => {}
        }
    }
    assert!(completed, "sz -e download never completed");
    let got = std::fs::read(dest_dir.join("payload.bin")).expect("downloaded file");
    assert_eq!(got, data, "escaped-mode bytes differ");
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("sz -e did not exit promptly (ZSINIT unacknowledged?)")
        .expect("sz wait failed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_cancels_a_real_sz_transfer() {
    if !tool_available("sz") {
        eprintln!("SKIP abort_cancels_a_real_sz_transfer: `sz` not installed");
        return;
    }
    let dir = scratch("abort");
    let dest_dir = dir.join("incoming");
    std::fs::create_dir_all(&dest_dir).unwrap();
    // Big enough that the transfer is still mid-flight when we abort.
    let src = dir.join("big.bin");
    let data: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    let mut child = Command::new("sz")
        .arg("-b")
        .arg(&src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx);
    spawn_writer(child_in, wire_out_rx);

    let abort = Arc::new(AtomicBool::new(false));
    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: abort.clone(),
    };
    let driver = tokio::spawn(run(
        Direction::Download,
        TransferSpec::Download { dest_dir, budget: None, resume_owner: None },
        Vec::new(),
        io,
    ));

    // Request cancel once the transfer is genuinely under way (first
    // byte-progress report), like the overlay's Cancel button.
    let watcher = tokio::spawn(async move {
        let mut outcome = None;
        while let Some(p) = progress_rx.recv().await {
            match p {
                Progress::Advanced { .. } => abort.store(true, std::sync::atomic::Ordering::Relaxed),
                Progress::Aborted => outcome = Some("aborted"),
                Progress::Completed { .. } => outcome = Some("completed"),
                Progress::Error(_) => outcome = Some("error"),
                _ => {}
            }
        }
        outcome
    });

    // The driver must TERMINATE (not hang) after the abort: that's the
    // whole point of the cooperative ZCAN. Outcome may be Aborted or,
    // if the machine finished the file first, Completed, but never a
    // deadlock.
    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("aborted transfer deadlocked")
        .unwrap();
    let outcome = watcher.await.unwrap();
    assert!(
        matches!(outcome, Some("aborted") | Some("completed")),
        "unexpected outcome: {outcome:?}"
    );
    // The real sz must exit rather than wait forever for more acks.
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("sz did not exit after cancel");
    let _ = status;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Multi-file upload: both files ride one ZMODEM session, and the
/// driver reports the batch position ("k of n") per file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_multiple_files_to_real_rz() {
    if !tool_available("rz") {
        eprintln!("SKIP upload_multiple_files_to_real_rz: `rz` not installed");
        return;
    }
    let dir = scratch("ul-multi");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let files = [
        ("a.bin", payload()),
        ("b.bin", (0..4096u32).map(|i| (i % 97) as u8).collect::<Vec<_>>()),
    ];
    let mut sources = Vec::new();
    for (name, data) in &files {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        sources.push(p);
    }

    let mut child = Command::new("rz")
        .arg("-b")
        .current_dir(&recv_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx);
    spawn_writer(child_in, wire_out_rx);

    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: Arc::new(AtomicBool::new(false)),
    };
    let driver = tokio::spawn(run(
        Direction::Upload,
        TransferSpec::Upload {
            sources,
            streaming_window: DEFAULT_STREAMING_WINDOW,
        },
        Vec::new(),
        io,
    ));
    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("multi-file upload deadlocked")
        .unwrap();

    let mut completed = false;
    let mut batches = Vec::new();
    while let Ok(p) = progress_rx.try_recv() {
        match p {
            Progress::Completed { .. } => completed = true,
            Progress::Started { batch, .. } => batches.push(batch),
            Progress::Error(e) => panic!("upload error: {e}"),
            _ => {}
        }
    }
    assert!(completed, "multi-file upload never completed");
    assert_eq!(batches, vec![Some((1, 2)), Some((2, 2))]);
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("rz did not exit promptly after multi-file session")
        .expect("rz wait failed");
    for (name, data) in &files {
        let got = std::fs::read(recv_dir.join(name)).unwrap_or_else(|_| panic!("missing {name}"));
        assert_eq!(&got, data, "{name} bytes differ");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_to_real_rz() {
    if !tool_available("rz") {
        eprintln!("SKIP upload_to_real_rz: `rz` (lrzsz) not installed");
        return;
    }
    let dir = scratch("ul");
    let recv_dir = dir.join("recv");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let src = dir.join("upload.bin");
    let data = payload();
    std::fs::write(&src, &data).unwrap();

    // The real receiver: `rz -b` writes whatever it receives into its
    // working directory, under the advertised name.
    let mut child = Command::new("rz")
        .arg("-b")
        .current_dir(&recv_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rz");
    let child_out = child.stdout.take().unwrap();
    let child_in = child.stdin.take().unwrap();

    let (wire_in_tx, wire_in) = mpsc::unbounded_channel();
    let (wire_out, wire_out_rx) = mpsc::unbounded_channel();
    let (progress, mut progress_rx) = mpsc::unbounded_channel();
    spawn_reader(child_out, wire_in_tx); // rz stdout -> our sender
    spawn_writer(child_in, wire_out_rx); // our frames -> rz stdin

    let io = TransferIo {
        wire_in,
        wire_out,
        progress,
        abort: Arc::new(AtomicBool::new(false)),
    };
    let driver = tokio::spawn(run(
        Direction::Upload,
        TransferSpec::Upload {
            sources: vec![src],
            streaming_window: DEFAULT_STREAMING_WINDOW,
        },
        Vec::new(),
        io,
    ));

    tokio::time::timeout(Duration::from_secs(30), driver)
        .await
        .expect("upload deadlocked")
        .unwrap();

    let mut completed = false;
    while let Ok(p) = progress_rx.try_recv() {
        match p {
            Progress::Completed { .. } => completed = true,
            Progress::Error(e) => panic!("upload error: {e}"),
            _ => {}
        }
    }
    assert!(completed, "sender never reported Completed");
    // The upload mirror of the issue #77 bound: rz reads our "OO"
    // sign-off (queued behind the completion event) and must exit
    // promptly once it arrives.
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("rz did not exit promptly after session end (OO not flushed?)")
        .expect("rz wait failed");
    let got = std::fs::read(recv_dir.join("upload.bin")).expect("rz-written file");
    assert_eq!(got, data, "rz received different bytes than we sent");
    let _ = std::fs::remove_dir_all(&dir);
}
