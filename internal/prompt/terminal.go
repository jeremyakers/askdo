package prompt

import (
	"bufio"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// TerminalReader reads operator input from a terminal file (typically
// os.Stdin). Line always performs a plain buffered read; Secret disables
// echo via TCGETS/TCSETS ioctls when the file is a TTY and falls back to a
// visible read (reporting hidden=false) when it is not.
type TerminalReader struct {
	file *os.File
	buf  *bufio.Reader
}

// NewTerminalReader returns a TerminalReader reading from file, which must
// stay open for the reader's lifetime.
func NewTerminalReader(file *os.File) *TerminalReader {
	return &TerminalReader{file: file, buf: bufio.NewReader(file)}
}

// IsTerminal reports whether file is a terminal (the TCGETS ioctl succeeds).
func IsTerminal(file *os.File) bool {
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}

// Line implements Reader.
func (r *TerminalReader) Line() (string, error) {
	return r.readLine()
}

// Secret implements Reader. On a TTY the ECHO flag is cleared before the
// read and the saved termios is restored on every return path (defer); a
// fatal signal mid-read leaves restoration to the shell, which is the
// accepted "within reason" signal-safety bound for a root-side CLI. When
// echo cannot be disabled (not a TTY, or the ioctls fail) the read falls
// back to a visible line and hidden=false.
func (r *TerminalReader) Secret() (hidden bool, line string, err error) {
	fd := int(r.file.Fd())
	saved, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		line, err := r.readLine()
		return false, line, err
	}
	noEcho := *saved
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
		line, err := r.readLine()
		return false, line, err
	}
	defer func() {
		if restoreErr := unix.IoctlSetTermios(fd, unix.TCSETS, saved); err == nil {
			err = restoreErr
		}
	}()
	line, err = r.readLine()
	return true, line, err
}

// readLine consumes one line from the shared buffer, stripping the trailing
// CR/LF. A partial final line (EOF after data) is returned as a complete
// answer; exhaustion with no data maps to ErrEndOfInput.
func (r *TerminalReader) readLine() (string, error) {
	line, err := r.buf.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return trimLineEnding(line), nil
		}
		if errors.Is(err, io.EOF) {
			return "", ErrEndOfInput
		}
		return "", err
	}
	return trimLineEnding(line), nil
}

func trimLineEnding(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}
