package com.example.SpringsecurityJWT.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class BasicException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final String errorMessage;

    public BasicException(String errorMessage, HttpStatus httpStatus) {
        this.errorMessage = errorMessage;
        this.httpStatus = httpStatus;
    }
}