use std::{
    ffi, fs,
    io::Write,
    os::unix::prelude::RawFd,
    path::{self, PathBuf},
};

use nix::{
    fcntl, libc, mount, sched,
    sys::{signal, socket, wait},
    unistd,
};

fn main() {
    let hostname = "lunis-01";
    let (socket1, socket2) = socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::SeqPacket,
        None,
        socket::SockFlag::empty(),
    )
    .expect("socketpair failed");

    fcntl::fcntl(socket1, fcntl::FcntlArg::F_SETFD(fcntl::FdFlag::FD_CLOEXEC))
        .expect("fcntl failed");

    const stack_size: usize = 1024 * 1024;
    let mut stack = [0u8; stack_size];

    let flags = sched::CloneFlags::CLONE_NEWNS
        | sched::CloneFlags::CLONE_NEWCGROUP
        | sched::CloneFlags::CLONE_NEWPID
        | sched::CloneFlags::CLONE_NEWIPC
        | sched::CloneFlags::CLONE_NEWNET
        | sched::CloneFlags::CLONE_NEWUTS;
    let child_pid = sched::clone(
        Box::new(|| child(socket2)),
        &mut stack,
        flags,
        Some(signal::SIGCHLD as i32),
    )
    .expect("=> clone failed!");

    cgroups(hostname, child_pid);

    handle_uid_map(child_pid, socket1);
    wait::waitpid(Some(child_pid), None).unwrap();

    free_resources(hostname);
}

fn child(socket: RawFd) -> isize {
    unistd::sethostname("lunis-01").unwrap();
    mounts();
    userns(socket);
    capabilities();
    syscalls();

    let path = ffi::CString::new("/bin/sh").unwrap();
    unistd::execv(&path, &[&path]).unwrap();

    return 0;
}

fn mounts() {
    print!("=> remounting everything with MS_PRIVATE...");
    mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        mount::MsFlags::MS_REC | mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .expect("failed");
    println!("remounted");

    print!("=> making a temp directory and a bind mount there...");
    let mount_dir = path::PathBuf::from("/tmp/lunis");
    fs::create_dir_all(&mount_dir).expect("failed making a directory!");
    // let (_, mount_dir) = unistd::mkstemp(mount_dir).expect("failed making a directory!");
    mount::mount(
        Some("./rootfs"),
        &mount_dir,
        None::<&str>,
        mount::MsFlags::MS_BIND | mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .expect("bind mount failed");

    let inner_mount_dir = mount_dir.join("oldroot");
    fs::create_dir_all(&inner_mount_dir).expect("failed making a directory!");
    // unistd::mkstemp(&inner_mount_dir).expect("failed making a directory!");
    println!("done.");

    print!("=> pivoting root...");
    unistd::pivot_root(&mount_dir, &inner_mount_dir).expect("failed!");
    println!("done.");

    let old_root_dir = inner_mount_dir.file_name().unwrap();
    let old_root = old_root_dir;

    print!("=> unmounting {:?}...", old_root);
    unistd::chdir("/").expect("chdir failed!");
    mount::umount2(old_root, mount::MntFlags::MNT_DETACH).expect("umount failed!");
    fs::remove_dir_all(old_root).expect("rmdir failed!");

    fs::create_dir_all("/proc").unwrap();
    mount::mount(
        None::<&str>,
        "/proc",
        Some("proc"),
        mount::MsFlags::empty(),
        None::<&str>,
    )
    .unwrap();

    fs::create_dir_all("/dev").unwrap();
    mount::mount(
        None::<&str>,
        "/dev",
        Some("devtmpfs"),
        mount::MsFlags::empty(),
        None::<&str>,
    )
    .unwrap();

    println!("done.");
}

fn userns(socket: RawFd) {
    print!("=> trying a user namespace...");
    let ok = sched::unshare(sched::CloneFlags::CLONE_NEWUSER).is_ok();
    unistd::write(socket, &[ok as u8]).unwrap();
    println!("done.");

    let mut buf = [0; 1];
    unistd::read(socket, &mut buf).unwrap();
    if buf[0] == 0 {
        return;
    }

    let uid = unistd::Uid::from_raw(1000);
    let gid = unistd::Gid::from_raw(1000);
    print!("=> switching to uid {} / gid {}..", uid, gid);
    unistd::setgroups(&[gid]).unwrap();
    unistd::setresuid(uid, uid, uid).unwrap();
    unistd::setresgid(gid, gid, gid).unwrap();
    println!("done.");
}

fn handle_uid_map(child_pid: unistd::Pid, socket: RawFd) {
    let userns_offset = 10000;
    let userns_count = 2000;
    let content = format!("0 {} {}\n", userns_offset, userns_count);

    let mut buf = [0; 1];
    unistd::read(socket, &mut buf).unwrap();
    if buf[0] == 0 {
        unistd::write(socket, &[0]).unwrap();
        return;
    }

    for file in ["uid_map", "gid_map"] {
        let path = format!("/proc/{}/{}", child_pid, file);
        print!("writing {}...", path);
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|mut f| f.write(content.as_bytes()))
            .unwrap();
    }
    unistd::write(socket, &[1]).unwrap();
}

fn capabilities() {
    use caps::Capability::*;
    print!("=> dropping capabilities...");
    let drop_caps = [
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM,
    ];

    print!("bounding and inheritable...");
    for cap in drop_caps {
        caps::drop(None, caps::CapSet::Bounding, cap).unwrap();
        caps::drop(None, caps::CapSet::Inheritable, cap).unwrap();
    }
    println!("done.");
}

fn syscalls() {
    use syscallz::Cmp::*;
    use syscallz::Syscall::*;
    let fail = syscallz::Action::Errno(libc::EPERM as u16);

    let isuid = libc::S_ISUID as u64;
    let isgid = libc::S_ISGID as u64;

    let ucmp1 = &[syscallz::Comparator::new(1, MaskedEq, isuid, Some(isuid))];
    let gcmp1 = &[syscallz::Comparator::new(1, MaskedEq, isgid, Some(isgid))];
    let ucmp2 = &[syscallz::Comparator::new(2, MaskedEq, isuid, Some(isuid))];
    let gcmp2 = &[syscallz::Comparator::new(2, MaskedEq, isgid, Some(isgid))];
    let cncmp = &[syscallz::Comparator::new(
        0,
        MaskedEq,
        libc::CLONE_NEWUSER as u64,
        Some(libc::CLONE_NEWUSER as u64),
    )];
    let ticmp = &[syscallz::Comparator::new(
        1,
        syscallz::Cmp::MaskedEq,
        libc::TIOCSTI as u64,
        Some(libc::TIOCSTI as u64),
    )];

    let rules1 = [
        (chmod, ucmp1),
        (chmod, gcmp1),
        (fchmod, ucmp1),
        (fchmod, gcmp1),
        (fchmodat, ucmp2),
        (fchmodat, gcmp2),
        (unshare, cncmp),
        (clone, cncmp),
        (ioctl, ticmp),
    ];

    let rules2 = [
        keyctl,
        add_key,
        request_key,
        ptrace,
        mbind,
        migrate_pages,
        move_pages,
        set_mempolicy,
        userfaultfd,
        perf_event_open,
    ];

    print!("=> filtering syscalls...");
    let mut ctx = syscallz::Context::init_with_action(syscallz::Action::Allow).unwrap();
    for rule in rules1 {
        ctx.set_rule_for_syscall(fail, rule.0, rule.1).unwrap();
    }

    for rule in rules2 {
        ctx.set_action_for_syscall(fail, rule).unwrap();
    }
    ctx.load().unwrap();

    println!("done.");
}

fn cgroups(hostname: &str, child_pid: unistd::Pid) {
    print!("=> setting cgroups...");

    let base_path = PathBuf::from("/sys/fs/cgroup");
    let name = format!("lunis/{}", hostname);

    let settings = [
        ("cpu", vec![("cpu.shares", "1")]),
        (
            "memory",
            vec![
                ("memory.limit_in_bytes", "1048576"),
                ("memory.kmem.limit_in_bytes", "1048576"),
            ],
        ),
        ("pids", vec![("pids.max", "64")]),
        ("blkio", vec![("blkio.weight", "64")]),
    ];

    for (controller, items) in settings {
        print!("{}...", controller);
        let path = base_path.join(controller).join(&name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("tasks"), format!("{}", child_pid)).unwrap();
        for item in items {
            if let Err(_) = fs::write(path.join(item.0), item.1) {
                println!(
                    "Your kernel does not support cgroup {}/{}",
                    controller, item.0
                );
            }
        }
    }

    println!("done.")
}

fn free_resources(hostname: &str) {
    print!("=> cleaning cgroups...");

    let controllers = ["cpu", "memory", "pids", "blkio"];
    for controller in controllers {
        print!("{}...", controller);
        let path = format!("/sys/fs/cgroup/{}/lunis/{}", controller, hostname);
        fs::remove_dir(path).expect("rmdir failed");
    }

    println!("done.");
}
