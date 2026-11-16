import socket

# Host-side victim: plain TCP listener with the smallest possible SYN queue
# (backlog 1).  Minimum backlog keeps exactly one control request socket in
# play per race attempt, so the slab slot freed by our RST is the one the
# cookie request reuses - no unrelated allocations in between.
# The kernel serving this socket is the host kernel itself.
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8081))
s.listen(1)
while True:
    try:
        c, _ = s.accept()
        c.close()
    except OSError:
        pass
