// Package inspection provides the broker's descriptor-relative, read-only host
// filesystem inspection boundary.
//
// Call ProbeOpenat2 during daemon startup (NewPolicy also calls it), then build
// a Policy with NewPolicy. ReadRange returns only a bounded span of a
// permitted regular file, ListDir lists a permitted directory, and Check
// validates a path against policy without granting content access. All
// methods enforce configured and built-in denies against the actual opened
// object.
package inspection
