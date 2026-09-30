package broker

import (
	"encoding/base64"
	"encoding/json"

	"github.com/jeremyakers/askdo/internal/proto"
)

// recordCapturedStdinRead is called only after a validated inspect result was
// written to the worker. Neither a model's assertions nor failed/withheld
// reads add coverage. A compact bitmap handles overlapping/out-of-order reads
// without accumulating unbounded request ranges.
func (j *jobRuntime) recordCapturedStdinRead(request proto.InspectRequest, result proto.InspectResult) {
	if j.req.CapturedStdinBase64 == "" || request.Op != "read_path" || result.Status != "ok" {
		return
	}
	var path proto.ReadPathRequest
	var delivered proto.ReadPathResult
	if json.Unmarshal(request.Payload, &path) != nil || path.Base != "bundle" || path.Path != "stdin" || json.Unmarshal(result.Payload, &delivered) != nil {
		return
	}
	if j.stdinReadBits == nil {
		data, err := base64.StdEncoding.DecodeString(j.req.CapturedStdinBase64)
		if err != nil || len(data) == 0 {
			return
		}
		j.stdinReadSize = int64(len(data))
		j.stdinReadBits = make([]byte, (len(data)+7)/8)
	}
	size := j.stdinReadSize
	start, end := delivered.Offset, delivered.NextOffset
	if start < 0 || end < start || end > size || end-start != int64(len(delivered.Content)) || path.Offset != start {
		return
	}
	for pos := start; pos < end; pos++ {
		index, bit := pos/8, byte(1<<uint(pos%8))
		if j.stdinReadBits[index]&bit == 0 {
			j.stdinReadBits[index] |= bit
			j.stdinReadCount++
		}
	}
	if delivered.EOF && end == size {
		j.stdinReadEOF = true
	}
}

// A fallback model has a fresh conversation. Without a broker-authenticated
// model-turn boundary, reads across choices cannot be attributed to the final
// model, so report coverage as unverified rather than combining attempts.
func (j *jobRuntime) capturedStdinFullyRead(history []proto.ModelHistoryEntry) bool {
	if len(history) != 1 || history[0].Outcome != "ok" || !j.stdinReadEOF {
		return false
	}
	return j.stdinReadSize > 0 && j.stdinReadCount == j.stdinReadSize
}
