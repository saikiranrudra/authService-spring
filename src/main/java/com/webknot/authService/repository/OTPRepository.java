package com.webknot.authService.repository;

import com.webknot.authService.model.OTP;
import com.webknot.authService.model.OtpType;
import com.webknot.authService.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OTPRepository extends JpaRepository<OTP, Long> {
    OTP findTopByConsumerIdAndOtpTypeOrderByCreatedAtDesc(User consumerId, OtpType otpType);
}
