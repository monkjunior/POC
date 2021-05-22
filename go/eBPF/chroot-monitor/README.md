# Learn how to user Golang with eBPF

## A simple application to monitor [*chroot(2)*](https://man7.org/linux/man-pages/man2/chroot.2.html) call

We will load eBPF instructions as a [kprobe](https://www.kernel.org/doc/Documentation/kprobes.txt). Remember kprobe is not a stable API.

List available tracepoints
```markdown
cat /sys/kernel/tracing/available_events | grep chroot
```

### Commands:
```markdown
sudo pacman -S bcc bcc-tools python-bcc
go get github.com/iovisor/gobpf
```


[gobpf](https://github.com/iovisor/gobpf) is a Go library that leverages the bcc project to make working with eBPF programs from Go simple

- Good [starting point](https://github.com/iovisor/iomodules/tree/master/hover/bpf)

