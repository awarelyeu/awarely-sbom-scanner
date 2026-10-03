package inventory

// These readers inspect bounded snapshots, never execute SQL or load database
// engines. Formats: sqlite.org/fileformat.html and Berkeley DB db_page.h.
import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
)

var errRPMDB = errors.New("invalid, changing or unsupported RPM database; retry after package updates finish")

const maxRPMHeader = 32 << 20

// sqliteRecords visits only the named ordinary table through sqlite_schema.
func sqliteRecords(ctx context.Context, b []byte, emit func([]byte) error) error {
	if len(b) < 512 || string(b[:16]) != "SQLite format 3\x00" {
		return errRPMDB
	}
	size := int(binary.BigEndian.Uint16(b[16:18]))
	if size == 1 {
		size = 65536
	}
	if size < 512 || size > 65536 || size&(size-1) != 0 || len(b)%size != 0 || b[20] != 0 || binary.BigEndian.Uint32(b[56:60]) != 1 || binary.BigEndian.Uint32(b[28:32]) != uint32(len(b)/size) {
		return errRPMDB
	}
	pages := len(b) / size
	used := map[int]bool{}
	page := func(n int) ([]byte, error) {
		if n < 1 || n > pages || used[n] {
			return nil, errRPMDB
		}
		used[n] = true
		return b[(n-1)*size : n*size], nil
	}
	var walk func(int, int, func([]byte) error) error
	walk = func(n, depth int, visit func([]byte) error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if depth > 32 {
			return errRPMDB
		}
		p, e := page(n)
		if e != nil {
			return e
		}
		off := 0
		if n == 1 {
			off = 100
		}
		typ := p[off]
		if typ != 5 && typ != 13 {
			return errRPMDB
		}
		h := 8
		if typ == 5 {
			h = 12
		}
		count := int(binary.BigEndian.Uint16(p[off+3 : off+5]))
		if off+h+count*2 > size {
			return errRPMDB
		}
		for i := 0; i < count; i++ {
			pos := int(binary.BigEndian.Uint16(p[off+h+2*i : off+h+2*i+2]))
			if pos < off+h+count*2 || pos >= size {
				return errRPMDB
			}
			if typ == 5 {
				if pos+4 > size {
					return errRPMDB
				}
				if e = walk(int(binary.BigEndian.Uint32(p[pos:pos+4])), depth+1, visit); e != nil {
					return e
				}
				continue
			}
			amount, k := sqliteVarint(p[pos:])
			if k == 0 || amount > maxRPMHeader {
				return errRPMDB
			}
			pos += k
			_, k = sqliteVarint(p[pos:])
			if k == 0 {
				return errRPMDB
			}
			pos += k
			local := int(amount)
			maxLocal := size - 35
			if local > maxLocal {
				minLocal := ((size - 12) * 32 / 255) - 23
				local = minLocal + (int(amount)-minLocal)%(size-4)
				if local > maxLocal {
					local = minLocal
				}
			}
			if pos+local > size {
				return errRPMDB
			}
			payload := p[pos : pos+local]
			if local < int(amount) {
				if pos+local+4 > size {
					return errRPMDB
				}
				next := int(binary.BigEndian.Uint32(p[pos+local : pos+local+4]))
				v := make([]byte, 0, int(amount))
				v = append(v, payload...)
				for len(v) < int(amount) {
					q, err := page(next)
					if err != nil {
						return err
					}
					next = int(binary.BigEndian.Uint32(q[:4]))
					take := min(size-4, int(amount)-len(v))
					v = append(v, q[4:4+take]...)
				}
				if next != 0 {
					return errRPMDB
				}
				payload = v
			}
			if e = visit(payload); e != nil {
				return e
			}
		}
		if typ == 5 {
			return walk(int(binary.BigEndian.Uint32(p[off+8:off+12])), depth+1, visit)
		}
		return nil
	}
	root := 0
	if err := walk(1, 0, func(raw []byte) error {
		r, e := sqliteRecord(raw)
		if e != nil {
			return e
		}
		if len(r) != 5 {
			return errRPMDB
		}
		if string(r[0]) == "table" && string(r[1]) == "Packages" && string(r[2]) == "Packages" {
			if root != 0 || len(r[3]) > 4 || len(r[3]) == 0 {
				return errRPMDB
			}
			for _, v := range r[3] {
				root = root*256 + int(v)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if root == 0 {
		return errRPMDB
	}
	count := 0
	return walk(root, 0, func(raw []byte) error {
		count++
		if count > 50000 {
			return errRPMDB
		}
		r, e := sqliteRecord(raw)
		if e != nil || len(r) != 2 || len(r[0]) != 0 || len(r[1]) < 8 {
			return errRPMDB
		}
		return emit(r[1])
	})
}
func sqliteVarint(b []byte) (uint64, int) {
	var n uint64
	for i := 0; i < min(len(b), 9); i++ {
		if i == 8 {
			return n<<8 | uint64(b[i]), 9
		}
		n = n<<7 | uint64(b[i]&127)
		if b[i] < 128 {
			return n, i + 1
		}
	}
	return 0, 0
}
func sqliteRecord(b []byte) ([][]byte, error) {
	h, k := sqliteVarint(b)
	if k == 0 || h > uint64(len(b)) || h < uint64(k) || h > 1024 {
		return nil, errRPMDB
	}
	pos := int(h)
	var out [][]byte
	for k < int(h) {
		typ, n := sqliteVarint(b[k:int(h)])
		if n == 0 {
			return nil, errRPMDB
		}
		k += n
		length := uint64(0)
		switch {
		case typ == 0:
		case typ >= 1 && typ <= 4:
			length = typ
		case typ == 5:
			length = 6
		case typ == 6 || typ == 7:
			length = 8
		case typ == 8:
			out = append(out, []byte{0})
			continue
		case typ == 9:
			out = append(out, []byte{1})
			continue
		case typ >= 12:
			length = (typ - 12) / 2
		default:
			return nil, errRPMDB
		}
		if length > uint64(len(b)-pos) {
			return nil, errRPMDB
		}
		out = append(out, b[pos:pos+int(length)])
		pos += int(length)
	}
	if pos != len(b) {
		return nil, errRPMDB
	}
	return out, nil
}

// BDB hash layout cross-checked against go-rpmdb (MIT, see THIRD_PARTY_NOTICES).
// Only active hash records are consumed; overflow chains are bounded and unique.
func bdbRecords(ctx context.Context, b []byte, emit func([]byte) error) error {
	if len(b) < 512 {
		return errRPMDB
	}
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint32(b[12:16]) != 0x61561 {
		order = binary.BigEndian
	}
	if order.Uint32(b[12:16]) != 0x61561 || order.Uint32(b[16:20]) != 9 || b[24] != 0 || b[25] != 8 || b[26] != 0 {
		return errRPMDB
	}
	size := int(order.Uint32(b[20:24]))
	if size < 512 || size > 65536 || size&(size-1) != 0 || len(b)%size != 0 {
		return errRPMDB
	}
	pages := len(b) / size
	if int(order.Uint32(b[32:36])) != pages-1 {
		return errRPMDB
	}
	used := map[int]bool{}
	get := func(n int) ([]byte, error) {
		if n < 1 || n >= pages || used[n] {
			return nil, errRPMDB
		}
		used[n] = true
		return b[n*size : (n+1)*size], nil
	}
	// Free pages may retain obsolete record bytes; exclude them explicitly.
	for n := int(order.Uint32(b[28:32])); n != 0; {
		p, e := get(n)
		if e != nil {
			return e
		}
		n = int(order.Uint32(p[16:20]))
	}
	count := 0
	for n := 1; n < pages; n++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p := b[n*size : (n+1)*size]
		if used[n] || (p[25] != 13 && p[25] != 2) {
			continue
		}
		used[n] = true
		if int(order.Uint32(p[8:12])) != n {
			return errRPMDB
		}
		entries := int(order.Uint16(p[20:22]))
		if entries%2 != 0 || 26+2*entries > size {
			return errRPMDB
		}
		last := size
		for i := 0; i < entries; i++ {
			off := int(order.Uint16(p[26+2*i : 28+2*i]))
			if off < 26+2*entries || off >= last {
				return errRPMDB
			}
			end := last
			last = off
			if i%2 == 0 {
				continue
			}
			var blob []byte
			switch p[off] {
			case 1:
				blob = p[off+1 : end]
			case 3:
				if off+12 > end {
					return errRPMDB
				}
				next := int(order.Uint32(p[off+4 : off+8]))
				length := int(order.Uint32(p[off+8 : off+12]))
				if length < 1 || length > maxRPMHeader {
					return errRPMDB
				}
				blob = make([]byte, 0, length)
				for next != 0 {
					q, e := get(next)
					if e != nil || q[25] != 7 {
						return errRPMDB
					}
					next = int(order.Uint32(q[16:20]))
					take := size - 26
					if next == 0 {
						take = int(order.Uint16(q[22:24]))
					}
					if take < 1 || take > size-26 || len(blob)+take > length {
						return errRPMDB
					}
					blob = append(blob, q[26:26+take]...)
				}
				if len(blob) != length {
					return errRPMDB
				}
			default:
				return errRPMDB
			}
			if len(blob) == 4 {
				continue
			} // database's next-record counter, not an RPM header
			count++
			if count > 50000 {
				return errRPMDB
			}
			if err := emit(blob); err != nil {
				return err
			}
		}
	}
	return nil
}

func rpmRecords(ctx context.Context, b []byte, emit func([]byte) error) error {
	if bytes.HasPrefix(b, []byte("SQLite format 3\x00")) {
		return sqliteRecords(ctx, b, emit)
	}
	return bdbRecords(ctx, b, emit)
}
