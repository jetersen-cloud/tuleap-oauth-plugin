package io.jenkins.plugins.tuleap_oauth;

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.guice.TuleapOAuth2GuiceModule;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import jnr.ffi.annotations.In;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;

import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

import static com.google.common.base.Charsets.UTF_8;

public class TuleapSecurityRealm extends SecurityRealm {

    private String tuleapUri;
    private String clientId;
    private Secret clientSecret;

    private static final String LOGIN_URL = "securityRealm/commenceLogin";
    private static final String AUTHORIZATION_ENDPOINT = "oauth2/authorize?";

    public static final String STATE_SESSION_ATTRIBUTE = "state";
    private static final String REDIRECT_URI = "securityRealm/finishLogin";

    private static final String SCOPE = "read:project";

    private static final String URL_CHARACTERS_ALLOWED =  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    private AuthorizationCodeChecker authorizationCodeChecker;
    private PluginHelper pluginHelper;

    @DataBoundConstructor
    public TuleapSecurityRealm(String tuleapUri, String clientId, String clientSecret) {
        this.setTuleapUri(Util.fixEmptyAndTrim(tuleapUri));
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.setClientSecret(Util.fixEmptyAndTrim(clientSecret));
    }

    @Inject
    public void setAuthorizationCodeChecker(AuthorizationCodeChecker authorizationCodeChecker) {
        this.authorizationCodeChecker = authorizationCodeChecker;
    }

    @Inject
    public void setPluginHelper(PluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    public String getTuleapUri() {
        return tuleapUri;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    private void setTuleapUri(String tuleapUri) {
        if (!StringUtils.isBlank(tuleapUri) && !tuleapUri.endsWith("/")) {
            tuleapUri = tuleapUri.concat("/");
        }
        this.tuleapUri = tuleapUri;
    }

    private void setClientSecret(String secretString) {
        this.clientSecret = Secret.fromString(secretString);
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            public Authentication authenticate(Authentication authentication)
                throws AuthenticationException {
                if (authentication instanceof UsernamePasswordAuthenticationToken) {
                    return authentication;
                }
                throw new BadCredentialsException(
                    "Unexpected authentication type: " + authentication);
            }
        });
    }

    @Override
    public String getLoginUrl() {
        return LOGIN_URL;
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        this.injectInstances();

        auth.setAuthenticated(false);
        Jenkins jenkins = this.getJenkinsInstance();
        if (jenkins.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath() + "/" + TuleapLogoutAction.REDIRECT_ON_LOGOUT + "/";
    }

    public HttpResponse doCommenceLogin(StaplerRequest request) throws UnsupportedEncodingException {
        this.injectInstances();

        final String state = this.buildStateRandomString();
        request.getSession().setAttribute(STATE_SESSION_ATTRIBUTE, state);

        final String rootUrl = this.getJenkinsInstance().getRootUrl();

        final String redirectUri = URLEncoder.encode(rootUrl + REDIRECT_URI, UTF_8.name());

        return new HttpRedirect(this.tuleapUri + AUTHORIZATION_ENDPOINT +
            "response_type=code" +
            "&client_id=" + this.clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=" + SCOPE +
            "&state=" + state
        );
    }

    private void injectInstances() {
        if (this.pluginHelper == null ||
            this.authorizationCodeChecker == null
        ) {
            Guice.createInjector(new TuleapOAuth2GuiceModule()).injectMembers(this);
        }
    }

    private String buildStateRandomString() {
        final SecureRandom secureRandom = new SecureRandom();
        final StringBuilder stateStringBuilder = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            stateStringBuilder.append(URL_CHARACTERS_ALLOWED.charAt(secureRandom.nextInt(URL_CHARACTERS_ALLOWED.length())));
        }
        return stateStringBuilder.toString();
    }

    public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) throws Exception {
        if (!this.authorizationCodeChecker.checkAuthorizationCode(request)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR + "/");
        }

        this.authenticateAsAdmin(request);

        return HttpResponses.redirectToContextRoot();
    }

    private Jenkins getJenkinsInstance() {
        return this.pluginHelper.getJenkinsInstance();
    }

    private void authenticateAsAdmin(StaplerRequest request) {
        User admin = User.getById("admin", true);
        if (admin == null) {
            throw new UsernameNotFoundException("Admin user cannot be retrieved...");
        }

        UserDetails adminDetails = admin.getUserDetailsForImpersonation();
        UsernamePasswordAuthenticationToken adminAuthToken = new UsernamePasswordAuthenticationToken(
            adminDetails.getUsername(),
            adminDetails.getPassword(),
            adminDetails.getAuthorities()
        );

        HttpSession session = request.getSession(false);
        if (session != null) {
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);

        SecurityContextHolder.getContext().setAuthentication(adminAuthToken);
        SecurityListener.fireAuthenticated(adminDetails);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "Tuleap Authentication";
        }
    }
}
