package emailupdate

type UpdateEmailRequest struct {
	// The current email of the user
	CurrentEmail string `json:"current_email" binding:"required,email"`
	// The new email to be updated
	NewEmail string `json:"new_email" binding:"required,email"`
	// The User ID of the user making the request
	UserID    string `json:"user_id" binding:"required"`
}

type UpdateEmailResponse struct {
	// The status of the email update request
	Status string `json:"status"`
	// The message to be displayed to the user
	Message string `json:"message"`
	// The new email address
	NewEmail string `json:"new_email"`
}