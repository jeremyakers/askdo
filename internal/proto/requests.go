package proto

// The wire types below ask a component to do something, so decoding refuses a
// field they do not define (see Request). A type belongs here only if dropping
// an unknown field could change what is done; a type that reports or describes
// something must not be listed.

// Client requests to the broker.
func (TimestampRequest) IsRequest()    {}
func (ReserveRequest) IsRequest()      {}
func (SubmitRequest) IsRequest()       {}
func (StatusRequest) IsRequest()       {}
func (AttachRequest) IsRequest()       {}
func (CancelRequest) IsRequest()       {}
func (AutoApprovalRequest) IsRequest() {}

// Worker tool and model requests to the broker, and their arguments. The
// reviewer decodes the model's tool-call arguments into the same types.
func (InspectRequest) IsRequest()         {}
func (ReadPathRequest) IsRequest()        {}
func (ListPathRequest) IsRequest()        {}
func (SearchPathRequest) IsRequest()      {}
func (StatPathRequest) IsRequest()        {}
func (FindPathRequest) IsRequest()        {}
func (MountInfoRequest) IsRequest()       {}
func (InspectionScopeRequest) IsRequest() {}
func (HashPathRequest) IsRequest()        {}
func (ServiceStatusRequest) IsRequest()   {}
func (SudoPolicyRequest) IsRequest()      {}
func (ModelTurnRequest) IsRequest()       {}

// The worker's one-use human decision authorizes the broker to dispatch a root
// command, or to refuse it. It is the only worker frame that does, so a field
// the broker does not define is refused rather than dropped from an approval.
func (Decision) IsRequest() {}
