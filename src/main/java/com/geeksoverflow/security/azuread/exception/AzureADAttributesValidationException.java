package com.geeksoverflow.security.azuread.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 27/11/17
 */
public class AzureADAttributesValidationException extends AuthenticationException {

    public AzureADAttributesValidationException(final String message) {
        super(message);
    }
}
