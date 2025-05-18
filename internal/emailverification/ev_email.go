package emailverification

type EmailSender interface {
	Send(to, subject, body string) error
}
