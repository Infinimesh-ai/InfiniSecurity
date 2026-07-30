//! SCM_RIGHTS 文件描述符传递(启动器 → daemon 移交 notify fd)。

use anyhow::{bail, Result};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// 经 unix socket 发送一个 fd,载荷为单字节 'F'。
pub fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let payload = [b'F'];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; unsafe { libc::CMSG_SPACE(4) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as usize;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            4,
        );
    }
    let rc = unsafe { libc::sendmsg(sock, &msg, 0) };
    if rc < 0 {
        bail!("sendmsg(SCM_RIGHTS) 失败: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// 接收一个 fd。返回 OwnedFd(带 CLOEXEC)。
pub fn recv_fd(sock: RawFd) -> Result<OwnedFd> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; unsafe { libc::CMSG_SPACE(4) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let rc = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if rc < 0 {
        bail!("recvmsg(SCM_RIGHTS) 失败: {}", std::io::Error::last_os_error());
    }
    if rc == 0 {
        bail!("对端在移交 fd 前关闭了连接");
    }
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            bail!("消息不含 SCM_RIGHTS 控制数据");
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            4,
        );
        if fd < 0 {
            bail!("收到非法 fd");
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// 便捷:对 std UnixStream 的封装。
pub fn send_fd_stream(stream: &std::os::unix::net::UnixStream, fd: RawFd) -> Result<()> {
    send_fd(stream.as_raw_fd(), fd)
}

pub fn recv_fd_stream(stream: &std::os::unix::net::UnixStream) -> Result<OwnedFd> {
    recv_fd(stream.as_raw_fd())
}
