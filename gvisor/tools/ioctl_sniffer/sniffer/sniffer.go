// Copyright 2024 The gVisor Authors.
// ... (license)

// Package sniffer parses the output of the ioctl hook.
package sniffer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/tools/ioctl_sniffer/ioctl_go_proto"
	"google.golang.org/protobuf/proto" // 新增
)

var (
	uvmDevPath    = "/dev/nvidia-uvm"
	ctlDevPath    = "/dev/nvidiactl"
	deviceDevPath = regexp.MustCompile(`/dev/nvidia(\d+)`)
)

// ioctlClass is the class of the ioctl. It mainly corresponds to the various
// parts where nvproxy supports branches.
type ioctlClass uint32

const (
	frontend ioctlClass = iota
	uvm
	control // Implies NV_ESC_RM_CONTROL frontend ioctl.
	alloc   // Implies NV_ESC_RM_ALLOC frontend ioctl.
	unknown // Implies unsupported Nvidia device file.
	_numClasses
)

func (c ioctlClass) String() string {
	switch c {
	case frontend:
		return "Frontend"
	case uvm:
		return "UVM"
	case control:
		return "Control"
	case alloc:
		return "Alloc"
	default:
		return "Unknown"
	}
}

// ioctlSubclass represents an instance of a given ioctlClass.
// - For frontend and uvm ioctls, this is IOC_NR(request).
// - For NV_ESC_RM_CONTROL frontend ioctl, this is the control command number.
// - For NV_ESC_RM_ALLOC frontend ioctl, this is the alloc class.
type ioctlSubclass uint32

var (
	supportedIoctls         [_numClasses]map[uint32]struct{}
	crashOnUnsupportedIoctl bool
)

// Ioctl contains the parsed ioctl protobuf information.
type Ioctl struct {
	pb       *pb.Ioctl
	class    ioctlClass
	subclass ioctlSubclass
	status   uint32 // Only valid for control and alloc ioctlClass.
}

// IsSupported returns true if the ioctl is supported by nvproxy.
func (i Ioctl) IsSupported() bool {
	if i.class == control && i.subclass&nvgpu.RM_GSS_LEGACY_MASK != 0 {
		// Legacy ioctls are a special case where nvproxy passes them through.
		return true
	}
	if i.class == control && (i.subclass>>16)&0xffff == nvgpu.NV2081_BINAPI {
		// NV2081_BINAPI control commands are a special case where nvproxy passes
		// them through.
		return true
	}
	if i.class == alloc && i.status == nvgpu.NV_ERR_INVALID_CLASS {
		return false
	}
	_, ok := supportedIoctls[i.class][uint32(i.subclass)]
	return ok
}

// String returns a string representation of the ioctl.
func (i Ioctl) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %#x %#x %#x %#x %#x", i.class, i.pb.GetRequest(), i.pb.GetRet(), i.subclass, i.status, len(i.pb.GetArgData()))
	if len(i.pb.GetParamsData()) > 0 {
		fmt.Fprintf(&sb, " (params %#x)", len(i.pb.GetParamsData()))
	}
	return sb.String()
}

// Init initializes the sniffer.
func Init() error {
	// 不依赖 nvconf，初始化空表即可（只影响“兼容性统计”，不影响 dump）
	for c := ioctlClass(0); c < _numClasses; c++ {
		supportedIoctls[c] = make(map[uint32]struct{})
	}
	return nil
}


// Results is a set of parsed ioctls.
type Results struct {
	unsupported map[ioctlClass][]ioctlSubclass
}

// Merge merges another Results into this one.
func (r *Results) Merge(other *Results) {
	if other == nil {
		return
	}
	for class, subs := range other.unsupported {
		r.unsupported[class] = append(r.unsupported[class], subs...)
		// 可选: sort/dedup if needed
		sort.Slice(r.unsupported[class], func(i, j int) bool {
			return r.unsupported[class][i] < r.unsupported[class][j]
		})
	}
}

// NewResults returns a new Results.
func NewResults() *Results {
	return &Results{unsupported: make(map[ioctlClass][]ioctlSubclass)}
}

// HasUnsupportedIoctl returns true if there are unsupported ioctls.
func (r *Results) HasUnsupportedIoctl() bool {
	return len(r.unsupported) > 0
}

// AddUnsupportedIoctl adds an unsupported ioctl to the results.
func (r *Results) AddUnsupportedIoctl(ioctl Ioctl) {
	r.unsupported[ioctl.class] = append(r.unsupported[ioctl.class], ioctl.subclass)
}

// String returns a string representation of the results.
func (r *Results) String() string {
	var sb strings.Builder
	for class := ioctlClass(0); class < _numClasses; class++ {
		if len(r.unsupported[class]) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "%s:\n", class)
		sort.Slice(r.unsupported[class], func(i, j int) bool {
			return r.unsupported[class][i] < r.unsupported[class][j]
		})
		for _, subclass := range r.unsupported[class] {
			fmt.Fprintf(&sb, "\t%#x\n", subclass)
		}
	}
	return sb.String()
}

// ParseIoctls parses a stream of ioctl protobufs.
func ParseIoctls(r io.Reader) *Results {
	res := NewResults()

	dumpFilePath := os.Getenv("GVISOR_IOCTL_DUMP_FILE")
	var dumpFile *os.File
	if dumpFilePath != "" {
		var err error
		dumpFile, err = os.OpenFile(dumpFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Warningf("Failed to open dump file %s: %v", dumpFilePath, err)
		}
		defer dumpFile.Close()
	}

	crashOnUnsupportedIoctl = os.Getenv("GVISOR_IOCTL_SNIFFER_ENFORCE_COMPATIBILITY") == "INSTANT"

	for {
		// Read the size of the protobuf.
		var size uint64
		err := binary.Read(r, binary.LittleEndian, &size)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Warningf("Failed to read size: %v", err)
			break
		}

		// Read the protobuf.
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			log.Warningf("Failed to read protobuf: %v", err)
			break
		}

		ioctlPB := &pb.Ioctl{}
		if err := proto.Unmarshal(buf, ioctlPB); err != nil {
			log.Warningf("Failed to unmarshal protobuf: %v", err)
			break
		}

		parsedIoctl, err := ParseIoctlOutput(ioctlPB)
		if err != nil {
			log.Warningf("Failed to parse ioctl: %v", err)
			continue
		}

		log.Debugf("%s", parsedIoctl)

		// 修改: 只dump pre-call (GetRet() == -1)，且只control/alloc
		if dumpFile != nil && parsedIoctl.pb.GetRet() == -1 && (parsedIoctl.class == control || parsedIoctl.class == alloc) {
			header := new(bytes.Buffer)
			binary.Write(header, binary.LittleEndian, uint32(0x4E564944)) // Magic 4B "NVID"
			binary.Write(header, binary.LittleEndian, parsedIoctl.pb.GetRequest()) // 8B
			binary.Write(header, binary.LittleEndian, uint32(0)) // ret固定0 (输入) 4B
			binary.Write(header, binary.LittleEndian, uint32(parsedIoctl.subclass)) // subclass 4B (从proto)
			
			var dumpData []byte
			var isSecondary bool
			if (parsedIoctl.class == control || parsedIoctl.class == alloc) && len(parsedIoctl.pb.GetParamsData()) > 0 {
				dumpData = parsedIoctl.pb.GetParamsData()  // 使用捕获到的二级 params
				isSecondary = true
			} else {
				dumpData = parsedIoctl.pb.GetArgData()  // 回退到一级 arg (Header)
				isSecondary = false
			}

			binary.Write(header, binary.LittleEndian, uint32(len(dumpData))) // arg_size 4B
			dumpFile.Write(header.Bytes())
			dumpFile.Write(dumpData)
			dumpFile.Sync()
			log.Debugf("Dumped pre raw ioctl: request=%#x, arg_size=%d (secondary=%t)", parsedIoctl.pb.GetRequest(), len(dumpData), isSecondary)
		}

		if !parsedIoctl.IsSupported() {
			res.AddUnsupportedIoctl(parsedIoctl)
			if crashOnUnsupportedIoctl {
				log.Warningf("Unsupported ioctl found; crashing immediately: %v", parsedIoctl)
				os.Exit(1)
			}
		}
	}
	return res
}

// ParseIoctlOutput parses an ioctl protobuf from the ioctl hook.
func ParseIoctlOutput(ioctl *pb.Ioctl) (Ioctl, error) {
	parsedIoctl := Ioctl{pb: ioctl}

	// Categorize and do class-specific parsing.
	path := ioctl.GetFdPath()
	switch {
	case path == uvmDevPath:
		parsedIoctl.class = uvm
		parsedIoctl.subclass = ioctlSubclass(ioctl.GetRequest())
	case path == ctlDevPath || deviceDevPath.MatchString(path):
		parsedIoctl.class = frontend
		parsedIoctl.subclass = ioctlSubclass(linux.IOC_NR(uint32(ioctl.GetRequest())))

		switch parsedIoctl.subclass {
		case nvgpu.NV_ESC_RM_CONTROL:
			data := ioctl.GetArgData()
			if uint32(len(data)) != nvgpu.SizeofNVOS54Parameters {
				return parsedIoctl, fmt.Errorf("unexpected number of bytes")
			}
			var ioctlParams nvgpu.NVOS54_PARAMETERS
			ioctlParams.UnmarshalBytes(data)

			parsedIoctl.class = control
			parsedIoctl.subclass = ioctlSubclass(ioctlParams.Cmd)
			parsedIoctl.status = ioctlParams.Status
		case nvgpu.NV_ESC_RM_ALLOC:
			data := ioctl.GetArgData()
			var isNVOS64 bool
			switch uint32(len(data)) {
			case nvgpu.SizeofNVOS21Parameters:
			case nvgpu.SizeofNVOS64Parameters:
				isNVOS64 = true
			default:
				return parsedIoctl, fmt.Errorf("unexpected number of bytes")
			}
			ioctlParams := nvgpu.GetRmAllocParamObj(isNVOS64)
			ioctlParams.UnmarshalBytes(data)

			parsedIoctl.class = alloc
			parsedIoctl.subclass = ioctlSubclass(ioctlParams.GetHClass())
			parsedIoctl.status = ioctlParams.GetStatus()
		}
	default:
		parsedIoctl.class = unknown
		parsedIoctl.subclass = ioctlSubclass(linux.IOC_NR(uint32(ioctl.GetRequest())))
	}

	return parsedIoctl, nil
}