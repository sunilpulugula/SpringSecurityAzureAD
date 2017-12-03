package com.geeksoverflow.security.azuread.manager;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import com.geeksoverflow.security.azuread.exception.AzureADAttributesValidationException;
import com.geeksoverflow.security.azuread.exception.AzureADAuthenticationException;
import com.geeksoverflow.security.azuread.helper.AuthHelper;
import com.geeksoverflow.security.azuread.model.AzureADClientProps;
import com.geeksoverflow.security.azuread.service.LocalUserDetailsService;
import com.geeksoverflow.security.azuread.service.RegisterUserDetailsService;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 26/11/17
 */
public class AzureADAuthenticationManager {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public static final String STATES = "states";
    public static final String STATE = "state";
    public static final Integer STATE_TTL = 3600;
    public static final String FAILED_TO_VALIDATE_MESSAGE = "Failed to validate data received from Authorization service - ";
    private String clientId = "";
    private String clientSecret = "";
    private String tenant = "";
    private String authority;

    private LocalUserDetailsService userDetailsService;
    private RegisterUserDetailsService registerUserDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;


    public AzureADAuthenticationManager(AzureADClientProps azureADProps) {
        this.clientId = azureADProps.getClientId();
        this.clientSecret = azureADProps.getClientSecret();
        this.tenant = azureADProps.getTenant();
        this.authority = azureADProps.getAuthority();
    }

    public boolean isAuthDataExpired(HttpServletRequest httpRequest) {
        AuthenticationResult authData = AuthHelper.getAuthSessionObject(httpRequest);
        return authData.getExpiresOnDate().before(new Date()) ? true : false;
    }

    public void updateAuthDataUsingRefreshToken(HttpServletRequest httpRequest) {
        AuthenticationResult authData =
                getAccessTokenFromRefreshToken(AuthHelper.getAuthSessionObject(httpRequest).getRefreshToken());
        setSessionPrincipal(httpRequest, authData);
    }

    public Authentication processAuthenticationData(HttpServletRequest httpRequest, String currentUri, String fullUrl) {
        Map<String, String> params = new HashMap();
        for (Object key : httpRequest.getParameterMap().keySet()) {
            String keyValue = (String) key;
            final String[] vals = (String[]) httpRequest.getParameterMap().get(key);
            params.put(keyValue, vals[0]);
        }
        // validate that state in response equals to state in request
        StateData stateData = validateState(httpRequest.getSession(), params.get(STATE));

        AuthenticationResponse authResponse = null;
        try {
            authResponse = AuthenticationResponseParser.parse(new URI(fullUrl), params);
        } catch (com.nimbusds.oauth2.sdk.ParseException | URISyntaxException e) {
            new AzureADAttributesValidationException(e.getMessage());
        }
        if (AuthHelper.isAuthenticationSuccessful(authResponse)) {
            AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;
            // validate that OIDC Auth Response matches Code Flow (contains only requested artifacts)
            validateAuthRespMatchesCodeFlow(oidcResponse);

            AuthenticationResult authData =
                    getAccessToken(oidcResponse.getAuthorizationCode(), currentUri);
            // validate nonce to prevent reply attacks (code maybe substituted to one with broader access)
            try {
                validateNonce(stateData, getClaimValueFromIdToken(authData.getIdToken(), "nonce"));
            } catch (Exception e) {
                new AzureADAttributesValidationException(e.getMessage());
            }

            // map to localuser, if user does not exist create user in database.
            // From next time onwards user will be mapped to local user
            Authentication authenticate = null;
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(authData.getUserInfo().getUniqueId(), authData.getUserInfo().getGivenName());
            try {
                authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
            } catch (AuthenticationException e) {
                registerUserDetailsService.register(authData.getUserInfo());
                authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
            }

            setSessionPrincipal(httpRequest, authData);
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            return authenticate;
        }
        AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
        throw new AzureADAttributesValidationException(String.format("Request for auth code failed: %s - %s",
                oidcResponse.getErrorObject().getCode(),
                oidcResponse.getErrorObject().getDescription()));
    }

    private void validateNonce(StateData stateData, String nonce) throws Exception {
        if (StringUtils.isEmpty(nonce) || !nonce.equals(stateData.getNonce())) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate nonce");
        }
    }

    private String getClaimValueFromIdToken(String idToken, String claimKey) throws ParseException {
        return (String) JWTParser.parse(idToken).getJWTClaimsSet().getClaim(claimKey);
    }

    public void sendAuthRedirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
        httpResponse.setStatus(302);

        // use state parameter to validate response fro
        // m Authorization server
        String state = UUID.randomUUID().toString();

        // use nonce parameter to validate idToken
        String nonce = UUID.randomUUID().toString();

        storeStateInSession(httpRequest.getSession(), state, nonce);

        String currentUri = httpRequest.getRequestURL().toString();
        throw new AzureADAuthenticationException(getRedirectUrl(currentUri, state, nonce));
    }

    /**
     * make sure that state is stored in the session,
     * delete it from session - should be used only once
     *
     * @param session
     * @param state
     * @throws Exception
     */
    private StateData validateState(HttpSession session, String state) {
        if (StringUtils.isNotEmpty(state)) {
            StateData stateDataInSession = removeStateFromSession(session, state);
            if (stateDataInSession != null) {
                return stateDataInSession;
            }
        }
        throw new AzureADAttributesValidationException(FAILED_TO_VALIDATE_MESSAGE + "could not validate state");
    }

    private void validateAuthRespMatchesCodeFlow(AuthenticationSuccessResponse oidcResponse) {
        if (oidcResponse.getIDToken() != null || oidcResponse.getAccessToken() != null ||
                oidcResponse.getAuthorizationCode() == null) {
            throw new AzureADAttributesValidationException(FAILED_TO_VALIDATE_MESSAGE + "unexpected set of artifacts received");
        }
    }

    private StateData removeStateFromSession(HttpSession session, String state) {
        Map<String, StateData> states = (Map<String, StateData>) session.getAttribute(STATES);
        if (states != null) {
            eliminateExpiredStates(states);
            StateData stateData = states.get(state);
            if (stateData != null) {
                states.remove(state);
                return stateData;
            }
        }
        return null;
    }

    private void storeStateInSession(HttpSession session, String state, String nonce) {
        if (session.getAttribute(STATES) == null) {
            session.setAttribute(STATES, new HashMap<String, StateData>());
        }
        ((Map<String, StateData>) session.getAttribute(STATES)).put(state, new StateData(nonce, new Date()));
    }

    private void eliminateExpiredStates(Map<String, StateData> map) {
        Iterator<Map.Entry<String, StateData>> it = map.entrySet().iterator();

        Date currTime = new Date();
        while (it.hasNext()) {
            Map.Entry<String, StateData> entry = it.next();
            long diffInSeconds = TimeUnit.MILLISECONDS.
                    toSeconds(currTime.getTime() - entry.getValue().getExpirationDate().getTime());

            if (diffInSeconds > STATE_TTL) {
                it.remove();
            }
        }
    }

    private AuthenticationResult getAccessTokenFromRefreshToken(
            String refreshToken) {
        AuthenticationContext context;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authority + tenant + "/", true,
                    service);
            Future<AuthenticationResult> future = context
                    .acquireTokenByRefreshToken(refreshToken, new ClientCredential(clientId, clientSecret), null, null);
            result = future.get();
        } catch (MalformedURLException | ExecutionException | InterruptedException e) {
            throw new AzureADAttributesValidationException(e.getMessage());
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new AzureADAttributesValidationException("authentication result was null");
        }
        return result;
    }

    private AuthenticationResult getAccessToken(
            AuthorizationCode authorizationCode, String currentUri) {
        String authCode = authorizationCode.getValue();
        ClientCredential credential = new ClientCredential(clientId,
                clientSecret);
        AuthenticationContext context;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authority + tenant + "/", true,
                    service);
            Future<AuthenticationResult> future = context
                    .acquireTokenByAuthorizationCode(authCode, new URI(
                            currentUri), credential, null);
            result = future.get();
        } catch (MalformedURLException | URISyntaxException | ExecutionException | InterruptedException e) {
            throw new AzureADAttributesValidationException(e.getCause().getMessage());
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new AzureADAttributesValidationException("authentication result was null");
        }
        return result;
    }

    private void setSessionPrincipal(HttpServletRequest httpRequest,
                                     AuthenticationResult result) {
        httpRequest.getSession().setAttribute(AuthHelper.PRINCIPAL_SESSION_NAME, result);
    }

    public void removePrincipalFromSession(HttpServletRequest httpRequest) {
        httpRequest.getSession().removeAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
    }

    private String getRedirectUrl(String currentUri, String state, String nonce)
            throws UnsupportedEncodingException {
        String redirectUrl = authority
                + this.tenant
                + "/oauth2/authorize?response_type=code&scope=openid&response_mode=form_post&redirect_uri="
                + URLEncoder.encode(currentUri, "UTF-8") + "&client_id="
                + clientId + "&resource=https%3a%2f%2fgraph.windows.net"
                + "&state=" + state
                + "&nonce=" + nonce;

        return redirectUrl;
    }


    private class StateData {
        private String nonce;
        private Date expirationDate;

        public StateData(String nonce, Date expirationDate) {
            this.nonce = nonce;
            this.expirationDate = expirationDate;
        }

        public String getNonce() {
            return nonce;
        }

        public Date getExpirationDate() {
            return expirationDate;
        }
    }

    public void setUserDetailsService(final LocalUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setRegisterUserDetailsService(final RegisterUserDetailsService registerUserDetailsService) {
        this.registerUserDetailsService = registerUserDetailsService;
    }
}
