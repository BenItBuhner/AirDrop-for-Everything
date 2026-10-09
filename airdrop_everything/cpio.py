"""Pure-Python CPIO archive support -- no libarchive needed.

AirDrop's /Upload carries a cpio archive inside DVZip framing. Apple writes
each file as "./<name>"; we write SVR4 "newc" (the portable format every
reader, including Apple's libarchive inside sharingd, auto-detects) and read
newc plus the older POSIX "odc" and binary formats for completeness.
"""
import io
import stat

NEWC_MAGIC = b"070701"
ODC_MAGIC = b"070707"
TRAILER = "TRAILER!!!"

_BLOCK = 512


def _align4(n):
    return (n + 3) & ~3


def write_newc(entries, out):
    """Write a newc cpio archive to a binary file object.

    entries: iterable of (arcname, data_bytes_or_fileobj, size) or
             (arcname, None, 0) for directories.
    arcname should already be "./name" style, as sharingd writes it.
    """
    ino = 1
    for name, data, size in entries:
        if data is None:
            mode = stat.S_IFDIR | 0o755
            size = 0
        else:
            mode = stat.S_IFREG | 0o644
        name_b = name.encode("utf-8", "surrogateescape")
        fields = [
            ino & 0xFFFFFFFF, mode, 0, 0, 1,          # ino mode uid gid nlink
            int(_mtime()) & 0xFFFFFFFF, size,          # mtime filesize
            3, 0, 0, 0,                                # devmajor devminor rdev*
            len(name_b) + 1, 0,                        # namesize check
        ]
        hdr = NEWC_MAGIC + b"".join(f"{f:08x}".encode() for f in fields)
        out.write(hdr + name_b + b"\0")
        pad = _align4(len(hdr) + len(name_b) + 1) - (len(hdr) + len(name_b) + 1)
        out.write(b"\0" * pad)
        remaining = size
        if data is not None:
            if hasattr(data, "read"):
                while remaining:
                    chunk = data.read(min(65536, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
            else:
                out.write(data)
                remaining -= len(data)
        if remaining > 0:
            out.write(b"\0" * remaining)
        out.write(b"\0" * (_align4(size) - size if size else 0))
        ino += 1
    name_b = TRAILER.encode() + b"\0"
    fields = [1, 0, 0, 0, 1, int(_mtime()) & 0xFFFFFFFF, 0, 3, 0, 0, 0,
              len(name_b), 0]
    hdr = NEWC_MAGIC + b"".join(f"{f:08x}".encode() for f in fields)
    out.write(hdr + name_b)
    pad = _align4(len(hdr) + len(name_b)) - (len(hdr) + len(name_b))
    out.write(b"\0" * pad)
    # newc archives pad to a multiple of 512 bytes
    pos = out.tell() if hasattr(out, "tell") else None
    if pos is not None:
        out.write(b"\0" * ((-_pos_helper(pos)) % _BLOCK))


def _pos_helper(pos):
    return pos


def _mtime():
    import time
    return time.time()


class Entry:
    """One archive member yielded by read()."""
    __slots__ = ("name", "size", "mode", "isfile", "isdir", "mtime")

    def __init__(self, name, size, mode, mtime=0):
        self.name = name
        self.size = size
        self.mode = mode
        self.isfile = stat.S_ISREG(mode)
        self.isdir = stat.S_ISDIR(mode)
        self.mtime = mtime


def read(stream):
    """Iterate (Entry, fileobj_slice) over a cpio stream.

    Supports newc (070701/070702) and odc (070707). Yields entries in order;
    the returned readable slice is valid only until the next iteration.
    """
    while True:
        magic = stream.read(6)
        if len(magic) < 6:
            return
        if magic in (NEWC_MAGIC, b"070702"):
            # 6-byte magic + 13 x 8-hex-digit fields = 110-byte header.
            hdr = stream.read(104)
            if len(hdr) < 104:
                return
            f = [int(hdr[i * 8:i * 8 + 8], 16) for i in range(13)]
            (ino, mode, uid, gid, nlink, mtime, size,
             devmaj, devmin, rdevmaj, rdevmin, namesize, check) = f
            name_b = stream.read(namesize)
            if len(name_b) < namesize:
                return
            name = name_b.rstrip(b"\0").decode("utf-8", "surrogateescape")
            _skip(stream, _align4(110 + namesize) - (110 + namesize))
            if name == TRAILER:
                return
            sl = _Slice(stream, size)
            yield Entry(name, size, mode, mtime), sl
            sl.read()                      # drain anything the caller skipped
            _skip(stream, _align4(size) - size)
        elif magic == ODC_MAGIC:
            # odc: 76-byte header, octal fields; mtime and filesize are
            # 11 chars wide, the rest 6.
            hdr = stream.read(70)
            if len(hdr) < 70:
                return
            def octf(a, b):
                return int(hdr[a:b], 8)
            mode = octf(12, 18)
            mtime = octf(42, 53)
            namesize = octf(53, 59)
            size = octf(59, 70)
            name_b = stream.read(namesize)
            if len(name_b) < namesize:
                return
            name = name_b.rstrip(b"\0").decode("utf-8", "surrogateescape")
            if name == TRAILER:
                return
            sl = _Slice(stream, size)
            yield Entry(name, size, mode, mtime), sl
            sl.read()
        else:
            raise ValueError(f"not a cpio archive (magic {magic!r})")


def _skip(stream, n):
    if n <= 0:
        return
    if hasattr(stream, "seek"):
        stream.seek(n, io.SEEK_CUR)
        return
    left = n
    while left:
        d = stream.read(left)
        if not d:
            return
        left -= len(d)


class _Slice(io.RawIOBase):
    """A read-only window over exactly `size` bytes of `stream`."""

    def __init__(self, stream, size):
        self._s = stream
        self._left = size

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0 or n > self._left:
            n = self._left
        if n == 0:
            return b""
        d = self._s.read(n)
        self._left -= len(d)
        return d


def iter_files(stream):
    """Convenience: yield (Entry, bytes) for regular files, fully buffered."""
    for entry, sl in read(stream):
        if entry.isfile:
            yield entry, sl.read()
        else:
            sl.read()
