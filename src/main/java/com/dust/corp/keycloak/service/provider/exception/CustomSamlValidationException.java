package com.dust.corp.keycloak.service.provider;

import org.springframework.security.saml2.Saml2Exception;

public class CustomSamlValidationException extends Saml2Exception {
    public CustomSamlValidationException(String message) {
        super(message);
    }
}