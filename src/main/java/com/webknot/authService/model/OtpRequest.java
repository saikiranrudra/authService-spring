package com.webknot.authService.model;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class OtpRequest {
    @NotBlank
    @Size(min = 6, max = 6)
    String otp;
}
