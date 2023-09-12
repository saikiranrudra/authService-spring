package com.webknot.authService.service;

import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class RandomNumber {
    private static Random random = new Random();
    private static final int MIN_VALUE = 100000; // Minimum 6-digit number (inclusive)
    private static final int MAX_VALUE = 999999; // Maximum 6-digit number (inclusive)

    public static int generateUnique6DigitNumber() {
        int randomNumber;
        randomNumber = random.nextInt(MAX_VALUE - MIN_VALUE + 1) + MIN_VALUE;
        return randomNumber;
    }
}
