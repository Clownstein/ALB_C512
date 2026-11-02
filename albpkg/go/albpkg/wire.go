package albpkg

import (
	"encoding/binary"
	"io"
	"os"
)

// byteReader is a bounds-checked cursor over an in-memory buffer.
//
// Cursor-based rather than reslice-and-reassign: repeated re-slicing of a
// large buffer is quadratic, which is the defect recorded against the research
// streaming API.
type byteReader struct {
	buf  []byte
	pos  int
	name string
}

func newByteReader(data []byte, name string) *byteReader {
	return &byteReader{buf: data, name: name}
}

func (r *byteReader) offset() int    { return r.pos }
func (r *byteReader) remaining() int { return len(r.buf) - r.pos }

func (r *byteReader) take(n int, what string) ([]byte, error) {
	if n < 0 {
		return nil, limitErrorf("negative length for %s", what)
	}
	end, err := checkedAdd(r.pos, n, int64(len(r.buf)), what+" offset")
	if err != nil || end > len(r.buf) {
		return nil, formatErrorf("truncated %s: %s needs %d bytes, %d remain",
			r.name, what, n, r.remaining())
	}
	out := r.buf[r.pos:end]
	r.pos = end
	return out, nil
}

func (r *byteReader) u8(what string) (int, error) {
	b, err := r.take(1, what)
	if err != nil {
		return 0, err
	}
	return int(b[0]), nil
}

func (r *byteReader) u16(what string) (int, error) {
	b, err := r.take(2, what)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

func (r *byteReader) u32(what string) (uint32, error) {
	b, err := r.take(4, what)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *byteReader) expect(literal []byte, what string) error {
	got, err := r.take(len(literal), what)
	if err != nil {
		return err
	}
	if !constantTimeBytesEqual(got, literal) {
		return formatErrorf("bad %s", what)
	}
	return nil
}

func (r *byteReader) finish() error {
	if r.remaining() != 0 {
		return formatErrorf("trailing bytes in %s: %d unconsumed", r.name, r.remaining())
	}
	return nil
}

// readExactAt reads exactly n bytes at the given offset. A short read is a
// format error, never a silently truncated buffer.
func readExactAt(f *os.File, n int, offset int64, what string) ([]byte, error) {
	if n < 0 {
		return nil, limitErrorf("negative read length for %s", what)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, offset); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, formatErrorf("truncated input: wanted %d bytes for %s", n, what)
		}
		return nil, wrapError(CategoryIO, err, "read failed for %s", what)
	}
	return buf, nil
}

// readAtMostAt reads up to n bytes at the given offset, looping over short
// reads and treating EOF as "that is all there is".
func readAtMostAt(f *os.File, n int, offset int64) ([]byte, error) {
	buf := make([]byte, n)
	got := 0
	for got < n {
		read, err := f.ReadAt(buf[got:], offset+int64(got))
		got += read
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, wrapError(CategoryIO, err, "read failed")
		}
	}
	return buf[:got], nil
}

// writeAll loops until every byte is written; a short write is an error.
func writeAll(f *os.File, data []byte) error {
	written := 0
	for written < len(data) {
		n, err := f.Write(data[written:])
		if err != nil {
			return wrapError(CategoryIO, err, "write failed")
		}
		written += n
	}
	return nil
}
