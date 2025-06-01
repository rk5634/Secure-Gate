package emailverification

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

// ev_ses_senderFileLogPrefix is the file-level log prefix for all log messages in this file
const ev_ses_senderFileLogPrefix = packageLogPrefix + "ev_ses_sender:"

// SESEmailSender handles sending emails using AWS SES
type SESEmailSender struct {
	client      *ses.Client
	senderEmail string
}

// NewSESClient creates a new SESEmailSender with AWS config
func NewSESClient(senderEmail string) (*SESEmailSender, error) {
	const funcName = "NewSESClient:"
	funcLogPrefix := ev_ses_senderFileLogPrefix + funcName

	log.Printf("%s creating SES client with sender email: %s", funcLogPrefix, senderEmail)

	// Load AWS config from environment or shared credentials
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Printf("%s failed to load AWS config: %v", funcLogPrefix, err)
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	sesClient := ses.NewFromConfig(cfg)

	log.Printf("%s SES client created successfully", funcLogPrefix)

	return &SESEmailSender{
		client:      sesClient,
		senderEmail: senderEmail,
	}, nil
}

// Send sends an email using AWS SES
func (s *SESEmailSender) Send(to, subject, body string) error {
	const funcName = "Send:"
	funcLogPrefix := ev_ses_senderFileLogPrefix + funcName

	log.Printf("%s preparing to send email to %s with subject: %s", funcLogPrefix, to, subject)

	if to == "" {
		log.Printf("%s recipient email is empty", funcLogPrefix)
		return errors.New("recipient email is empty")
	}

	input := &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: []string{to},
		},
		Message: &types.Message{
			Subject: &types.Content{
				Data: aws.String(subject),
			},
			Body: &types.Body{
				Text: &types.Content{
					Data: aws.String(body),
				},
			},
		},
		Source: aws.String(s.senderEmail),
	}

	_, err := s.client.SendEmail(context.TODO(), input)
	if err != nil {
		log.Printf("%s error sending email to %s: %v", funcLogPrefix, to, err)
		return err
	}

	log.Printf("%s email sent successfully to %s", funcLogPrefix, to)
	return nil
}
