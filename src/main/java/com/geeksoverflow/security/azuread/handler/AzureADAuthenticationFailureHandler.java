package com.geeksoverflow.security.azuread.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.geeksoverflow.security.azuread.exception.AzureADAttributesValidationException;
import com.geeksoverflow.security.azuread.exception.AzureADAuthenticationException;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 27/11/17
 */
public class AzureADAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private String redirectionUrl;

    public AzureADAuthenticationFailureHandler(String redirectionUrl) {
        this.redirectionUrl = redirectionUrl;
    }

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        if (failed instanceof AzureADAuthenticationException) {
            response.sendRedirect(((AzureADAuthenticationException) failed).getRedirectUrl());
            return;
        }else if(failed instanceof AzureADAttributesValidationException) {
            response.setStatus(500);
            request.setAttribute("message", failed.getMessage());
            request.getRequestDispatcher("/pages/accessdenied.jsp").forward(request, response);
        }
        response.sendRedirect(redirectionUrl);
    }



}