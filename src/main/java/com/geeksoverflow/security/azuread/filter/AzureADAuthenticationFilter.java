package com.geeksoverflow.security.azuread.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.geeksoverflow.security.azuread.helper.AuthHelper;
import com.geeksoverflow.security.azuread.manager.AzureADAuthenticationManager;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 26/11/17
 */
public class AzureADAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static Logger logger = LoggerFactory.getLogger(AzureADAuthenticationFilter.class);

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final AzureADAuthenticationManager azureADAuthenticationManager;


    public AzureADAuthenticationFilter(String defaultProcessUrl, AuthenticationSuccessHandler successHandler,
                                     AuthenticationFailureHandler failureHandler,AzureADAuthenticationManager azureADAuthenticationManager) {
        super(defaultProcessUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.azureADAuthenticationManager= azureADAuthenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws AuthenticationException, IOException, ServletException {

        Authentication authentication = null;
        try {
            String currentUri = httpRequest.getRequestURL().toString();
            String queryStr = httpRequest.getQueryString();
            String fullUrl = currentUri + (queryStr != null ? "?" + queryStr : "");

            // check if user has a AuthData in the session
            if (!AuthHelper.isAuthenticated(httpRequest)) {
                if (AuthHelper.containsAuthenticationData(httpRequest)) {
                    authentication = azureADAuthenticationManager.processAuthenticationData(httpRequest, currentUri, fullUrl);
                } else {
                    // not authenticated
                    azureADAuthenticationManager.sendAuthRedirect(httpRequest, httpResponse);
                }
            }
            if (azureADAuthenticationManager.isAuthDataExpired(httpRequest)) {
                azureADAuthenticationManager.updateAuthDataUsingRefreshToken(httpRequest);
            }
        } catch (AuthenticationException authException) {
            // something went wrong (like expiration or revocation of token)
            // we should invalidate AuthData stored in session and redirect to Authorization server
            azureADAuthenticationManager.removePrincipalFromSession(httpRequest);
            azureADAuthenticationManager.sendAuthRedirect(httpRequest, httpResponse);
        }
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}