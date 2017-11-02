package saml

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
)

// SAMLServiceProvider defines methods for Service Providers
type SAMLServiceProvider interface {
	Metadata() *EntityDescriptor
	MakeRedirectAuthenticationRequest(relayState string) (*url.URL, error)
	GetSSOBindingLocation(binding string) string
	getIDPSigningCert(entityID string) (*x509.Certificate, error)
	MakeAuthenticationRequest(idpURL string) (*AuthnRequest, error)
	MakePostAuthenticationRequest(relayState string) ([]byte, error)
	ParseResponse(req *http.Request, possibleRequestIDs []string) (*Assertion, error)
	validateAssertion(assertion *Assertion, possibleRequestIDs []string, now time.Time) error
	validateSigned(responseEl *etree.Element) error
	validateSignature(el *etree.Element) error
}
