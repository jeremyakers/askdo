package broker

import (
	"errors"
	"path/filepath"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

func (j *jobRuntime) handleInspect(request proto.InspectRequest) (proto.InspectResult, error) {
	payload, err := proto.DecodeInspectRequestPayload(request)
	if err != nil {
		return proto.InspectResult{}, err
	}
	switch value := payload.(type) {
	case proto.ReadPathRequest:
		return j.readPath(request.RequestSeq, value)
	case proto.ListPathRequest:
		return j.listPath(request.RequestSeq, value)
	case proto.SearchPathRequest:
		return j.searchPath(request.RequestSeq, value)
	case proto.StatPathRequest:
		return j.statPath(request.RequestSeq, value)
	case proto.FindPathRequest:
		return j.findPath(request.RequestSeq, value)
	case proto.MountInfoRequest:
		return j.mountInfo(request.RequestSeq, value)
	default:
		return proto.InspectResult{}, errors.New("unsupported inspection request")
	}
}

func (j *jobRuntime) recordWithheldPath(path string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.withheldPaths == nil {
		j.withheldPaths = make(map[string]struct{})
	}
	j.withheldPaths[filepath.Clean(path)] = struct{}{}
}

func (j *jobRuntime) recordMaskedBundlePath(ref string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.maskedBundlePaths == nil {
		j.maskedBundlePaths = make(map[string]struct{})
	}
	j.maskedBundlePaths[ref] = struct{}{}
}

func failedInspect(seq uint32, status inspection.Status) proto.InspectResult {
	if status == inspection.StatusError {
		status = inspection.StatusUnknown
	}
	return proto.InspectResult{Type: "inspect_result", RequestSeq: seq, Status: string(status)}
}

func truncateUTF8(value string, max int) string {
	if len(value) <= max {
		return value
	}
	value = value[:max]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
