package com.webknot.authService.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ForgotPasswordResponse {
    Integer otpNumber;
    String url;
}
