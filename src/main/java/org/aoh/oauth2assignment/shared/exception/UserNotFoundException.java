package org.aoh.oauth2assignment.shared.exception;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException (String message){
        super (message);
    }
}
