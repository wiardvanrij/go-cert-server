package parser

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"time"
)

const (
	logVersion           = 0
	certificateTimestamp = 0
	treeHash             = 1
	hashSHA256           = 4
	sigECDSA             = 3
)

const (
	X509Entry    LogEntryType = 0
	PreCertEntry LogEntryType = 1
)

// Log represents a public log.
type Log struct {
	Root string
	Key  *ecdsa.PublicKey
}

type LogEntryType uint16

type Entry struct {
	// Timestamp is the raw time value from the log.
	Timestamp uint64
	// Time is Timestamp converted to a time.Time
	Time              time.Time
	Type              LogEntryType
	X509Cert          []byte
	PreCertIssuerHash []byte
	TBSCert           []byte
	ExtraCerts        [][]byte

	LeafInput []byte
	ExtraData []byte
}

type EntryAndPosition struct {
	Index uint64
	// Offset contains the byte offset from the beginning of the file for
	// this entry.
	Offset int64
	// Length contains the number of bytes in this entry on disk.
	Length int
	// Raw contains the compressed contents of the entry.
	Raw []byte
	// Entry contains the parsed entry.
	Entry *Entry
}

func ParseEntry(leafData, extraData []byte) (*Entry, error) {
	x := leafData
	if len(x) < 2 {
		return nil, errors.New("ct: truncated entry")
	}
	if x[0] != logVersion {
		return nil, errors.New("ct: unknown entry version")
	}
	if x[1] != 0 {
		return nil, errors.New("ct: unknown leaf type")
	}
	x = x[2:]

	entry := new(Entry)
	if len(x) < 8 {
		return nil, errors.New("ct: truncated entry")
	}
	entry.Timestamp = binary.BigEndian.Uint64(x)
	entry.Time = time.Unix(int64(entry.Timestamp/1000), int64(entry.Timestamp%1000))
	x = x[8:]

	if len(x) < 2 {
		return nil, errors.New("ct: truncated entry")
	}
	entry.Type = LogEntryType(x[1])
	x = x[2:]
	switch entry.Type {
	case X509Entry:
		if len(x) < 3 {
			return nil, errors.New("ct: truncated entry")
		}
		l := int(x[0])<<16 |
			int(x[1])<<8 |
			int(x[2])
		x = x[3:]
		if len(x) < l {
			return nil, errors.New("ct: truncated entry")
		}
		entry.X509Cert = x[:l]
		x = x[l:]
	case PreCertEntry:
		if len(x) < 32 {
			return nil, errors.New("ct: truncated entry")
		}
		entry.PreCertIssuerHash = x[:32]
		x = x[32:]
		if len(x) < 2 {
			return nil, errors.New("ct: truncated entry")
		}
		l := int(x[0])<<8 | int(x[1])
		if len(x) < l {
			return nil, errors.New("ct: truncated entry")
		}
		entry.TBSCert = x[:l]
	default:
		return nil, errors.New("ct: unknown entry type")
	}

	x = extraData
	if len(x) > 0 {
		if len(x) < 3 {
			return nil, errors.New("ct: extra data truncated")
		}
		l := int(x[0])<<16 | int(x[1])<<8 | int(x[2])
		x = x[3:]

		if l != len(x) {
			return nil, errors.New("ct: extra data truncated")
		}

		for len(x) > 0 {
			if len(x) < 3 {
				return nil, errors.New("ct: extra data truncated")
			}
			l := int(x[0])<<16 | int(x[1])<<8 | int(x[2])
			x = x[3:]

			if l > len(x) {
				return nil, errors.New("ct: extra data truncated")
			}
			entry.ExtraCerts = append(entry.ExtraCerts, x[:l])
			x = x[l:]
		}
	}

	entry.LeafInput = leafData
	entry.ExtraData = extraData

	return entry, nil
}
