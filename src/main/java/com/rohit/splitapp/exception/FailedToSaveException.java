package com.rohit.splitapp.exception;

public class FailedToSaveException extends RuntimeException {

    public FailedToSaveException() {
        super();
    }
    public FailedToSaveException(String message) {
        super(message);
    }

    public FailedToSaveException(String message, Throwable cause) {
        super(message, cause);
    }

}
