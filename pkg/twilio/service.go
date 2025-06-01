package twilio

import (


	"github.com/twilio/twilio-go"
	verify "github.com/twilio/twilio-go/rest/verify/v2"
	
)

type TwilioService struct {
	Client           *twilio.RestClient
	VerifyServiceSID string
}

func NewTwilioService(accountSID, authToken, verifyServiceSID string) *TwilioService {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})
	return &TwilioService{Client: client, VerifyServiceSID: verifyServiceSID}
}

func (t *TwilioService) SendOTP(phone string) error {
	params := &verify.CreateVerificationParams{}
	params.SetTo(phone)
	params.SetChannel("sms")

	_, err := t.Client.VerifyV2.CreateVerification(t.VerifyServiceSID, params)
	return err
}

func (t *TwilioService) VerifyOTP(phone, code string) (bool, error) {
	params := &verify.CreateVerificationCheckParams{}
	params.SetTo(phone)
	params.SetCode(code)

	resp, err := t.Client.VerifyV2.CreateVerificationCheck(t.VerifyServiceSID, params)
	if err != nil {
		return false, err
	}
	return *resp.Status == "approved", nil
}
