package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
)

func (resp *Response) Parse(req *http.Request, possibleRequestIDs []string, sp ServiceProvider) (*Assertion, error) {
	now := TimeNow()
	retErr := &InvalidResponseError{
		Now:      now,
		Response: req.PostForm.Get("SAMLResponse"),
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
		return nil, retErr
	}
	retErr.Response = string(rawResponseBuf)

	// do some validation first before we decrypt
	if err := xml.Unmarshal(rawResponseBuf, &resp); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal response: %s", err)
		return nil, retErr
	}
	dv := DestinationValidator{
		resp.Destination,
		sp.AcsURL,
	}
	if err := dv.Validate(); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	requestIDvalid := false
	for _, possibleRequestID := range possibleRequestIDs {
		if resp.InResponseTo == possibleRequestID {
			requestIDvalid = true
		}
	}
	if !requestIDvalid {
		retErr.PrivateErr = fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs)
		return nil, retErr
	}

	iiv := IssueInstantValidator{
		MaxIssueDelay,
		now,
	}
	if err := iiv.Validate(); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	iv := IssuerValidator{
		*resp.Issuer,
		sp.IDPMetadata.EntityID,
	}
	if err := iv.Validate(); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	if resp.Status.StatusCode.Value != StatusSuccess {
		retErr.PrivateErr = fmt.Errorf("Status code was not %s", StatusSuccess)
		return nil, retErr
	}

	var assertion *Assertion
	if resp.EncryptedAssertion == nil {

		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		// TODO(ross): verify that the namespace is urn:oasis:names:tc:SAML:2.0:protocol
		responseEl := doc.Root()
		if responseEl.Tag != "Response" {
			retErr.PrivateErr = fmt.Errorf("expected to find a response object, not %s", doc.Root().Tag)
			return nil, retErr
		}

		if err = sp.validateSigned(resp.Issuer.Value, responseEl); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		assertion = resp.Assertion
	}

	// decrypt the response
	if resp.EncryptedAssertion != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
		el := doc.FindElement("//EncryptedAssertion/EncryptedData")
		plaintextAssertion, err := xmlenc.Decrypt(sp.Key, el)
		if err != nil {
			retErr.PrivateErr = fmt.Errorf("failed to decrypt response: %s", err)
			return nil, retErr
		}
		retErr.Response = string(plaintextAssertion)

		doc = etree.NewDocument()
		if err := doc.ReadFromBytes(plaintextAssertion); err != nil {
			retErr.PrivateErr = fmt.Errorf("cannot parse plaintext response %v", err)
			return nil, retErr
		}

		if err := sp.validateSigned(resp.Issuer.Value, doc.Root()); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		assertion = &Assertion{}
		if err := xml.Unmarshal(plaintextAssertion, assertion); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
	}

	if err := sp.validateAssertion(assertion, possibleRequestIDs, now); err != nil {
		retErr.PrivateErr = fmt.Errorf("assertion invalid: %s", err)
		return nil, retErr
	}

	return assertion, err
}
