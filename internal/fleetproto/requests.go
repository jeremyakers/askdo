package fleetproto

// A host's requests to the gateway ask it to do something, so their parsers
// refuse a field they do not define (see proto.Request). Everything the gateway
// signs or answers with reports something, and its parsers ignore the fields
// they do not know so that a newer gateway can add to what it reports.
func (TicketSubmission) IsRequest() {}
func (ModelTurn) IsRequest()        {}
func (JoinRequest) IsRequest()      {}
func (JoinReveal) IsRequest()       {}
