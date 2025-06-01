package services


import (
	"fmt"
)



func (s *userService) SendOTPService(phonenumber string) error {
	_, err := s.repo.GetUserByPhone(phonenumber)

	if err != nil {
		fmt.Printf("auth-system:internal:services:phone_service:SendOTPService: error fetching user by phone number: %v\n", err)
		return fmt.Errorf("user with this phone number does not exist")
	}

	err = s.twilioService.SendOTP(phonenumber)
	if err != nil {
		fmt.Printf("auth-system:internal:services:phone_service:SendOTPService: failed to send OTP: %v\n", err)
		return err
	}
	return nil
}



func (s *userService) VerifyOTPService(phonenumber, otp string) error {
	_, err := s.repo.GetUserByPhone(phonenumber)

	if err != nil {
		fmt.Printf("auth-system:internal:services:phone_service:VerifyOTPService: error fetching user by phone number: %v\n", err)
		return fmt.Errorf("user with this phone number does not exist")
	}

	verified, err := s.twilioService.VerifyOTP(phonenumber, otp)
	if err != nil {
		fmt.Printf("auth-system:internal:services:phone_service:VerifyOTPService: error during verification: %v\n", err)
		return err
	}
	if !verified {
		return fmt.Errorf("OTP verification failed")
	}

	// Update user status in the database
	err = s.repo.UpdatePhoneVerificationStatus(phonenumber, true)
	if err != nil {
		fmt.Printf("auth-system:internal:services:phone_service:VerifyOTPService: error updating phone verification status: %v\n", err)
		return err
	}
	return nil
}





