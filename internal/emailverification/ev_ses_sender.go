package emailverification

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
)

type SESEmailSender struct {
	client     *ses.Client
	senderEmail string
}

func NewSESClient(senderEmail string) (*SESEmailSender, error) {
	fmt.Printf("auth-system:internal:emailverification:ev_ses_sender: Creating SES client with sender email: %s\n", senderEmail)

	// Load AWS config from environment or shared credentials
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("auth-system:internal:emailverification:ev_ses_sender: Error loading AWS config: %v\n", err)
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	sesClient := ses.NewFromConfig(cfg)
	return &SESEmailSender{
		client:     sesClient,
		senderEmail: senderEmail,
	}, nil
}

func (s *SESEmailSender) Send(to, subject, body string) error {
	fmt.Printf("Sending email to %s with subject %s From %s\n", to, subject, s.senderEmail)
	if to == "" {
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
		fmt.Printf("auth-system:internal:emailverification:ev_ses_sender: Error sending email: %v\n", err)
	}
	return err
}
