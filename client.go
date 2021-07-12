package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/valyala/fasthttp"
)

var (
	badPasswordError = errors.New("bad password")
	badDataError     = errors.New("bad data")
	regexFindBody    = regexp.MustCompile(`"body":"{\\"subscription\\":(.*?)}}"`)
)

const (
	authURLTemplate         = "https://www.expressapisv2.net/apis/v2/credentials?client_version=11.5.2&installation_id=%s&os_name=ios&os_version=14.4"
	subscriptionURLTemplate = "https://www.expressapisv2.net/apis/v2/batch?client_version=11.5.2&installation_id=%s&os_name=ios&os_version=14.4"
	authDataTemplate        = `{"email":"%s","iv":"%s","key":"%s","password":"%s"}`
)

type User struct {
	Email        string
	Password     string
	Token        string `json:"access_token"`
	OvpnUsername string `json:"ovpn_username"`
	OvpnPassword string `json:"ovpn_password"`
	BillingCycle int    `json:"billing_cycle"`
	Status       string `json:"status"`
	AutoBill     bool   `json:"auto_bill"`
	ExpTime      int    `json:"expiration_time"`
}

type Client struct {
	Proxy  string
	client *fasthttp.Client
	aesKey []byte
	aesIv  []byte
	id     string
	User   *User
}

func (c *Client) auth() error {
	c.id = generateInstallID()
	c.client = &fasthttp.Client{
		Dial: c.Proxy,
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(fmt.Sprintf(authURLTemplate, c.id))
	req.Header.SetMethod("POST")

	c.aesKey, c.aesIv = generateAesKeys()
	plainData := fmt.Sprintf(authDataTemplate,
		c.User.Email,
		base64.StdEncoding.EncodeToString(c.aesIv),
		base64.StdEncoding.EncodeToString(c.aesKey),
		c.User.Password)
	gzippedData := gzipData([]byte(plainData))
	envelopedData := pkcs7Encrypt(gzippedData)
	bodySign := generateSignature(envelopedData)
	headersSign := generateSignature([]byte(fmt.Sprintf("POST /apis/v2/credentials?client_version=11.5.2&installation_id=%s&os_name=ios&os_version=14.4", c.id)))

	req.Header.Add("User-Agent", "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2")
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Expect", "")
	req.Header.Add("X-Body-Compression", "gzip")
	req.Header.Add("X-Signature", fmt.Sprintf("2 %s 91c776e", headersSign))
	req.Header.Add("X-Body-Signature", fmt.Sprintf("2 %s 91c776e", bodySign))
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("Accept-Language", "en")

	req.SetBody(envelopedData)

	err := c.client.Do(req, resp)
	if err != nil {
		return err
	}
	var decryptedResponse []byte
	switch resp.StatusCode() {
	case 401:
		return badPasswordError
	case 400:
		return badDataError
	case 200:
		decryptedResponse = decryptAes(resp.Body(), c.aesKey, c.aesIv)
	default:
		return badDataError
	}
	json.Unmarshal(decryptedResponse, c.User)

	return nil
}

func (c *Client) getSubscription() error {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(fmt.Sprintf(subscriptionURLTemplate, c.id))
	req.Header.SetMethod("POST")

	headersSign1 := generateSignature([]byte(fmt.Sprintf("POST /apis/v2/batch?client_version=11.5.2&installation_id=%s&os_name=ios&os_version=14.4", c.id)))

	headersSign2 := generateSignature([]byte(fmt.Sprintf("GET /apis/v2/subscription?access_token=%s&client_version=11.5.2&installation_id=%s&os_name=ios&os_version=14.4&reason=activation_with_email", c.User.Token, c.id)))

	body := fmt.Sprintf(`[{"headers":{"Accept-Language":"en","X-Signature":"2 %s 91c776e"},"method":"GET","url":"/apis/v2/subscription?access_token=%s&client_version=11.5.2&installation_id=%s&os_name=ios&os_version=14.4&reason=activation_with_email"}]`, headersSign2, c.User.Token, c.id)

	bodySign := generateSignature([]byte(body))

	req.Header.Add("User-Agent", "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2")
	//req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Expect", "")
	req.Header.Add("X-Signature", fmt.Sprintf("2 %s 91c776e", headersSign1))
	req.Header.Add("X-Body-Signature", fmt.Sprintf("2 %s 91c776e", bodySign))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-Language", "en")

	req.SetBody([]byte(body))

	err := c.client.Do(req, resp)
	if err != nil {
		return err
	}

	bodyR := string(resp.Body())

	if !strings.Contains(bodyR, "subscription") {
		return errors.New(bodyR)
	}

	found := regexFindBody.FindAllStringSubmatch(bodyR, -1)

	json.Unmarshal([]byte(strings.ReplaceAll(found[0][1], "\\", "")+"}"), c.User)

	return nil

}
