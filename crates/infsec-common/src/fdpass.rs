//! SCM_RIGHTS 文件描述符传递(启动器 → daemon 移交 notify fd)。
//!
//! 载荷与 fd 必须在**同一条** sendmsg 里:普通 `read()` 会静默丢弃
//! 附带的 fd,所以只要接收端在 recvmsg 之前对同一个 socket 做过任何
//! 带预读的普通读取(BufReader::read_line 就会),fd 就可能凭空消失。
//! 一次消息 = 一次握手,从设计上消掉这个竞态。

use anyhow::{bail, Result};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// hello 载荷上限。握手消息只有一条,超限即协议错误。
const MAX_PAYLOAD: usize = 512 * 1024;

/// 经 unix socket 发送一个 fd,附带任意字节载荷(需非空:
/// 内核不保证零长度消息一定把控制数据递过去)。
pub fn send_with_fd(sock: RawFd, payload: &[u8], fd: RawFd) -> Result<()> {
    if payload.is_empty() {
        bail!("载荷不能为空");
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
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
    if rc as usize != payload.len() {
        bail!("sendmsg 只发出 {rc}/{} 字节", payload.len());
    }
    Ok(())
}

/// 接收一条携带 fd 的消息,返回(载荷, fd)。fd 带 CLOEXEC。
pub fn recv_with_fd(sock: RawFd) -> Result<(Vec<u8>, OwnedFd)> {
    let mut payload = vec![0u8; MAX_PAYLOAD];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
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
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("控制数据被截断,fd 可能已丢失");
    }
    payload.truncate(rc as usize);
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
        Ok((payload, OwnedFd::from_raw_fd(fd)))
    }
}

/// 便捷:对 std UnixStream 的封装。
pub fn send_with_fd_stream(
    stream: &std::os::unix::net::UnixStream,
    payload: &[u8],
    fd: RawFd,
) -> Result<()> {
    send_with_fd(stream.as_raw_fd(), payload, fd)
}

pub fn recv_with_fd_stream(
    stream: &std::os::unix::net::UnixStream,
) -> Result<(Vec<u8>, OwnedFd)> {
    recv_with_fd(stream.as_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    /// 回归:载荷与 fd 必须一次到达,且 fd 真的可用。
    #[test]
    fn payload_and_fd_arrive_together() {
        let (a, b) = UnixStream::pair().unwrap();
        // 拿一个可辨识的 fd:临时文件写入已知内容
        let path = std::env::temp_dir().join(format!("infsec-fdpass-{}", std::process::id()));
        std::fs::write(&path, b"fdpass-ok").unwrap();
        let f = std::fs::File::open(&path).unwrap();

        send_with_fd_stream(&a, b"{\"hello\":1}\n", f.as_raw_fd()).unwrap();
        let (payload, fd) = recv_with_fd_stream(&b).unwrap();
        assert_eq!(payload, b"{\"hello\":1}\n");

        let mut received = std::fs::File::from(fd);
        let mut s = String::new();
        received.read_to_string(&mut s).unwrap();
        assert_eq!(s, "fdpass-ok", "收到的 fd 必须指向同一个打开文件");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_fd_is_an_error() {
        let (a, b) = UnixStream::pair().unwrap();
        std::io::Write::write_all(&mut (&a), b"no-fd-here").unwrap();
        assert!(recv_with_fd_stream(&b).is_err(), "无 SCM_RIGHTS 必须报错");
    }
}
