package fleetproto

import "reflect"

// CheckCatalog compares every fact against the root's expected frozen catalog,
// not a matching subset supplied by the proof. Unix seconds are caller supplied.
func CheckCatalog(got, frozen Catalog, now int64) error {
	if err := Validate(got); err != nil {
		return err
	}
	if err := Validate(frozen); err != nil {
		return err
	}
	if now <= 0 || now >= frozen.ExpiresAt {
		return ErrExpired
	}
	if !reflect.DeepEqual(got, frozen) {
		return ErrBinding
	}
	return nil
}

// CheckTicket establishes that a locally frozen ticket hashes the complete
// selected profile/route/display facts. Call before sending any ticket.
func CheckTicket(ticket Ticket, profiles []ProfileMetadata, routeSnapshot RouteSnapshot) error {
	if err := Validate(ticket); err != nil {
		return err
	}
	profileHash, err := HashProfiles(profiles)
	if err != nil {
		return err
	}
	if err := Validate(routeSnapshot); err != nil {
		return err
	}
	if ticket.Binding.ProfileHash != profileHash || ticket.Binding.RouteHash != routeSnapshot.Revision {
		return ErrBinding
	}
	return nil
}

// CheckReceipt requires the exact root-owned frozen binding and every recipient
// with every expected summary part and the correct card-or-notice variant. The
// signed receipt's own hashes/counts never define the root's expected facts.
// Cryptographic verification, one-use state and the local deadline remain the
// caller's responsibility; now must be within the unchanged frozen expiry.
func CheckReceipt(receipt Receipt, frozen Ticket, frozenRoute RouteSnapshot, now int64) error {
	if err := Validate(receipt); err != nil {
		return err
	}
	if err := Validate(frozen); err != nil {
		return err
	}
	if err := Validate(frozenRoute); err != nil {
		return err
	}
	if now <= 0 || now >= frozen.Binding.ExpiresAt {
		return ErrExpired
	}
	if receipt.Binding != frozen.Binding || frozen.Binding.RouteHash != frozenRoute.Revision || receipt.DeliveredAt > now || len(receipt.Deliveries) != len(frozenRoute.Recipients) {
		return ErrBinding
	}
	for i, recipient := range frozenRoute.Recipients {
		delivery := receipt.Deliveries[i]
		if !reflect.DeepEqual(delivery.Recipient, recipient) || len(delivery.SummaryMessageIDs) != frozen.Display.SummaryParts {
			return ErrBinding
		}
	}
	return nil
}

func CheckDecision(decision Decision, receipt Receipt, frozen Ticket, frozenRoute RouteSnapshot, now int64) error {
	if err := CheckReceipt(receipt, frozen, frozenRoute, now); err != nil {
		return err
	}
	if err := Validate(decision); err != nil {
		return err
	}
	hash, err := HashReceipt(receipt)
	if err != nil {
		return err
	}
	if decision.Binding != frozen.Binding || decision.ReceiptHash != hash || decision.BotID != frozenRoute.BotID || decision.DecidedAt < receipt.DeliveredAt || decision.DecidedAt > now {
		return ErrBinding
	}
	for _, delivery := range receipt.Deliveries {
		if delivery.Recipient.ChatID == decision.ChatID && delivery.CardMessageID == decision.CardMessageID {
			for _, id := range delivery.Recipient.OperatorUserIDs {
				if id == decision.OperatorID {
					return nil
				}
			}
		}
	}
	return ErrBinding
}

// CheckModelResult prevents a successful/error result from crossing sessions,
// revisions or turn ordering. Caller still enforces local budgets and deadline.
func CheckModelResult(result ModelResult, frozen ModelTurn, now int64) error {
	if err := Validate(result); err != nil {
		return err
	}
	if err := Validate(frozen); err != nil {
		return err
	}
	if now <= 0 || now >= frozen.Binding.Deadline {
		return ErrExpired
	}
	if result.Binding != frozen.Binding {
		return ErrBinding
	}
	return nil
}
