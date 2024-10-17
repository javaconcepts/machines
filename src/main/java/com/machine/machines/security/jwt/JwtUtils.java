package com.machine.machines.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${machine.app.JwtSecret}")
    private String jwtSecret;

    @Value("${machine.app.jwtExpirationMs}")
    private String jwtExpirationMs;

    
}