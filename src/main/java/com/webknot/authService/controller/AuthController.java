package com.webknot.authService.controller;

import com.webknot.authService.model.*;
import com.webknot.authService.repository.OTPRepository;
import com.webknot.authService.repository.RoleRepository;
import com.webknot.authService.repository.UserRepository;
import com.webknot.authService.security.jwt.JwtUtils;
import com.webknot.authService.service.RandomNumber;
import com.webknot.authService.service.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final OTPRepository otpRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if(userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken"));
        }

        if(userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email already exist"));
        }

        // Create new user's account
        User user = User.builder()
                .username(signupRequest.getUsername())
                .email(signupRequest.getEmail())
                .password(encoder.encode(signupRequest.getPassword()))
                .build();
        Set<String> strRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if(strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found"));

            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(adminRole);
                        break;

                    case "super_admin":
                        Role superAdmin = roleRepository.findByName(ERole.ROLE_SUPER_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(superAdmin);

                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User Registered Successfully!"));
    }

    @PostMapping("/forgot_password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPassword forgotPassword, HttpServletRequest request) {
        if(!StringUtils.hasText(forgotPassword.getEmail())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("email missing"));
        }

        User user = userRepository.findByEmail(forgotPassword.getEmail());

        if(user.getId() == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("User with email do not exist"));
        }

        int otpNumber = RandomNumber.generateUnique6DigitNumber();
        OTP otp = otp = OTP.builder()
                .otpType(OtpType.FORGOT_PASSWORD)
                .otp(otpNumber + "")
                .producerId(user)
                .consumerId(user)
                .build();

        otpRepository.save(otp);

        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new ForgotPasswordResponse(
                        otpNumber,
                        String.format("%s/api/auth/change_password?otp=%d&id=%d", baseUrl, otpNumber, user.getId())));
    }

    @GetMapping("/change_password")
    public ResponseEntity<?> changePassword(@RequestParam String otp, @RequestParam Long id, @RequestParam String password) {

        Optional<User> user = userRepository.findById(id);
        if(user.isPresent()) {

            OTP otpObj = otpRepository.findTopByConsumerIdAndOtpTypeOrderByCreatedAtDesc(
                    user.get(), OtpType.FORGOT_PASSWORD
            );

            if(otpObj.getOtp().equals(otp)) {
                System.out.println("I ot executed");
                User updatedUser = user.get();
                updatedUser.setPassword(passwordEncoder.encode(password));
                userRepository.save(updatedUser);

                return ResponseEntity
                        .status(HttpStatus.ACCEPTED)
                        .body(new MessageResponse("Password updated successfully"));
            }

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("invalid OTP"));
        }

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new MessageResponse("invalid id"));
    }
}
