package saml

import (
	"fmt"
	"net/url"
	"time"
)

type Validator interface {
	Validate() error
}

type DestinationValidator struct {
	Destination string
	AcsURL      url.URL
}

func (dv DestinationValidator) Validate() error {
	if dv.Destination != dv.AcsURL.String() {
		err := fmt.Errorf("`Destination` does not match AcsURL (expected %q)", dv.AcsURL.String())
		return err
	}
	return nil
}

type IssuerValidator struct {
	Issuer   Issuer
	EntityID string
}

func (iv IssuerValidator) Validate() error {
	if iv.Issuer.Value != iv.EntityID {
		return fmt.Errorf("issuer is not %q", iv.EntityID)
	}
	return nil
}

type IssueInstantValidator struct {
	MaxIssueDelay time.Duration
	IssueInstant  time.Time
}

func (iiv IssueInstantValidator) Validate() error {
	now := TimeNow()
	if iiv.IssueInstant.Add(iiv.MaxIssueDelay).Before(now) {
		return fmt.Errorf("expired on %s", iiv.IssueInstant.Add(iiv.MaxIssueDelay))
	}
	return nil
}

type SubjectValidator struct {
	Confirmations      []SubjectConfirmation
	AcsURL             url.URL
	MaxClockSkew       time.Duration
	PossibleRequestIDs []string
}

func (sv SubjectValidator) Validate() error {
	now := TimeNow()
	for _, subjectConfirmation := range sv.Confirmations {
		requestIDvalid := false
		for _, possibleRequestID := range sv.PossibleRequestIDs {
			if subjectConfirmation.SubjectConfirmationData.InResponseTo == possibleRequestID {
				requestIDvalid = true
				break
			}
		}
		if !requestIDvalid {
			return fmt.Errorf("SubjectConfirmation one of the possible request IDs (%v)", sv.PossibleRequestIDs)
		}
		if subjectConfirmation.SubjectConfirmationData.Recipient != sv.AcsURL.String() {
			return fmt.Errorf("SubjectConfirmation Recipient is not %s", sv.AcsURL.String())
		}
		if subjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Add(sv.MaxClockSkew).Before(now) {
			return fmt.Errorf("SubjectConfirmationData is expired")
		}
	}
	return nil
}
