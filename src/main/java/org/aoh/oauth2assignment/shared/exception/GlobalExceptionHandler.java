package org.aoh.oauth2assignment.shared.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UsernameNotFoundException.class)
    public Map<String, String> handleUserNotFound(UsernameNotFoundException usernameNotFoundException){
        Map<String, String> entryMap = new HashMap<>();
        entryMap.put("error message is ", usernameNotFoundException.getMessage());
        return entryMap;
    }

}
