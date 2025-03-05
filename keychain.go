package keychain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

const (
	PasswordNotIncluded = "Not Included"
	kErr                = "keychain error: "
)

var (
	PathAPW = "/opt/homebrew/bin/apw"
)

type Result struct {
	Account
	Domain string `json:"domain"`
}

type Account struct {
	Username string `json:"username"`
	Password string `json:"password"` // "Not Included" when not included
}

type Query struct {
	Results     []Result `json:"results"`
	Status      int      `json:"status"` // 0 == success
	ResultError string   `json:"error,omitempty"`
}

func (k Query) ErrorFmt() string {
	if k.Status == 0 && len(k.ResultError) == 0 {
		return kErr + "unknown"
	}

	return fmt.Sprintf("keychain (error %v): %s", k.Status, k.ResultError)
}

func (k Query) Error() error {
	if k.Status == 0 && len(k.ResultError) == 0 {
		return nil
	}

	return fmt.Errorf("%s", k.ErrorFmt())
}

type Map map[string][]Account
type Error int64

const (
	ErrorDefault Error = iota
	ErrorDomain
	ErrorAccount
	ErrorPassword
	ErrorPasswordNotIncluded
)

func (k Error) String() string {
	return k.Error()
}

func (k Error) Error() string {
	switch {
	case errors.Is(k, ErrorDomain):
		return kErr + "invalid domain"
	case errors.Is(k, ErrorAccount):
		return kErr + "invalid account"
	case errors.Is(k, ErrorPassword):
		return kErr + "empty password"
	case errors.Is(k, ErrorPasswordNotIncluded):
		return kErr + "password not included"
	default:
		return kErr + "unknown"
	}
}

func (k Account) GetPassword() (string, error) {
	if len(k.Password) == 0 {
		return "", ErrorPassword
	}

	if k.Password == PasswordNotIncluded {
		return k.Password, ErrorPasswordNotIncluded
	}

	return k.Password, nil
}

func (k Map) Get(domain, account string) (*Account, error) {
	d, ok := k[domain]
	if !ok {
		return nil, ErrorDomain
	}

	var a *Account
	for _, da := range d {
		if da.Username == account {
			a = &da
			break
		}
	}

	if a == nil {
		return nil, ErrorAccount
	}

	if _, err := a.GetPassword(); err != nil {
		return a, err
	}

	return a, nil
}

func (k Query) Map() (Map, error) {
	m := make(map[string][]Account)

	if err := k.Error(); err != nil {
		return m, err
	}

	for _, d := range k.Results {
		if a, ok := m[d.Domain]; ok {
			m[d.Domain] = append(a, d.Account)
		} else {
			da := make([]Account, 0)
			da = append(da, d.Account)
			m[d.Domain] = da
		}
	}

	return m, nil
}

func Retrieve(domain string) (*Query, error) {
	k, err := callAPW("pw", "get", domain)
	if err != nil {
		return nil, err
	}

	if k == nil {
		return nil, ErrorDefault
	}

	return k, nil
}

func RetrieveAccount(domain, account string) (*Account, error) {
	kq, err := Retrieve(domain)
	if err != nil {
		return nil, err
	}

	km, err := kq.Map()
	if err != nil {
		return nil, err
	}

	ka, err := km.Get(domain, account)
	if err != nil {
		return nil, err
	}

	return ka, nil
}

func callAPW(args ...string) (*Query, error) {
	out, err := exec.Command(PathAPW, args...).CombinedOutput()
	if err != nil && len(out) == 0 { // Only return error message if we have no stdout
		return nil, err
	}

	var k Query
	if err := json.Unmarshal(out, &k); err != nil {
		return nil, err
	}

	// Check for APW error in response
	if err := k.Error(); err != nil {
		return &k, err
	}

	return &k, nil
}
