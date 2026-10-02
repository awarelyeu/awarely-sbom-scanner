package inventory

import (
	"bytes"
	"context"
	"encoding/binary"
)

// SQLite's checksummed committed WAL frames are overlaid in memory. No writes,
// SQL execution, recovery, SHM mapping or extension loading take place.
func sqliteWAL(ctx context.Context, db, wal []byte) ([]byte, error) {
	if len(db) < 512 || len(wal) < 32 || !bytes.HasPrefix(db, []byte("SQLite format 3\x00")) {
		return nil, errRPMDB
	}
	be := binary.BigEndian
	magic := be.Uint32(wal[:4])
	if magic != 0x377f0682 && magic != 0x377f0683 || be.Uint32(wal[4:8]) != 3007000 {
		return nil, errRPMDB
	}
	size := int(be.Uint32(wal[8:12]))
	dsize := int(be.Uint16(db[16:18]))
	if dsize == 1 {
		dsize = 65536
	}
	if size != dsize || size < 512 || size > 65536 || size&(size-1) != 0 || (len(wal)-32)%(size+24) != 0 {
		return nil, errRPMDB
	}
	var order binary.ByteOrder = binary.LittleEndian
	if magic&1 != 0 {
		order = binary.BigEndian
	}
	var a, b uint32
	sum := func(v []byte) {
		for i := 0; i < len(v); i += 8 {
			a += order.Uint32(v[i:i+4]) + b
			b += order.Uint32(v[i+4:i+8]) + a
		}
	}
	sum(wal[:24])
	if a != be.Uint32(wal[24:28]) || b != be.Uint32(wal[28:32]) {
		return nil, errRPMDB
	}
	last, dbPages := 0, 0
	for off := 32; off < len(wal); off += size + 24 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		h := wal[off : off+24]
		if !bytes.Equal(h[8:16], wal[16:24]) {
			return nil, errRPMDB
		}
		sum(h[:8])
		sum(wal[off+24 : off+24+size])
		if a != be.Uint32(h[16:20]) || b != be.Uint32(h[20:24]) {
			return nil, errRPMDB
		}
		pg := int(be.Uint32(h[:4]))
		commit := int(be.Uint32(h[4:8]))
		if pg < 1 || pg > (128<<20)/size || commit > (128<<20)/size {
			return nil, errRPMDB
		}
		if commit > 0 {
			last = off
			dbPages = commit
		}
	}
	if last == 0 {
		return db, nil
	}
	out := make([]byte, dbPages*size)
	copy(out, db)
	for off := 32; off <= last; off += size + 24 {
		pg := int(be.Uint32(wal[off : off+4]))
		if pg <= dbPages {
			copy(out[(pg-1)*size:pg*size], wal[off+24:off+24+size])
		}
	}
	return out, nil
}
