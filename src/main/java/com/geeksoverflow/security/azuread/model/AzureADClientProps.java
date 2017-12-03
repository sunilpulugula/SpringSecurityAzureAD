package com.geeksoverflow.security.azuread.model;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 2/12/17
 */
public class AzureADClientProps {
    private String clientId;
    private String clientSecret;
    private String tenant;
    private String authority;

    public AzureADClientProps(final String clientId, final String clientSecret, final String tenant, final String authority) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tenant = tenant;
        this.authority = authority;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(final String tenant) {
        this.tenant = tenant;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(final String authority) {
        this.authority = authority;
    }
}
