package com.geeksoverflow.security.azuread.exception;

import java.net.URL;

import org.springframework.security.core.AuthenticationException;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 27/11/17
 */
public class AzureADAuthenticationException extends AuthenticationException {

    private final String redirectUrl;

    public AzureADAuthenticationException(URL redirectUrl) {
        this(redirectUrl.toString());
    }

    public AzureADAuthenticationException(String redirectUrl) {
        super("");
        this.redirectUrl = redirectUrl;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

}

