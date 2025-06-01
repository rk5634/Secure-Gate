package emailupdate

// UpdateEmailRequest represents the payload for updating a user's email.
// It includes the current email, the new email, and the user ID making the request.
type UpdateEmailRequest struct {
	// CurrentEmail is the user's current registered email address.
	// Required and must be a valid email format.
	CurrentEmail string `json:"current_email" binding:"required,email"`

	// NewEmail is the new email address to update to.
	// Required and must be a valid email format.
	NewEmail string `json:"new_email" binding:"required,email"`

	// UserID uniquely identifies the user making the update request.
	// Required field.
	UserID string `json:"user_id" binding:"required"`
}


// UpdateEmailResponse represents the response returned after attempting an email update.
type UpdateEmailResponse struct {
	// Status indicates the result of the email update operation (e.g., "success", "failure").
	Status string `json:"status"`

	// Message provides additional information or feedback regarding the operation.
	Message string `json:"message"`

	// NewEmail reflects the updated email address after a successful update.
	NewEmail string `json:"new_email,omitempty"`
}
