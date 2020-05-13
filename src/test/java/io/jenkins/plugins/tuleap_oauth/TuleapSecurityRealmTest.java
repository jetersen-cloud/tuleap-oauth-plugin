package io.jenkins.plugins.tuleap_oauth;

import com.google.gson.Gson;
import hudson.util.FormValidation;
import io.jenkins.plugins.tuleap_oauth.checks.AccessTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.IDTokenChecker;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelperImpl;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapAuthorizationCodeUrlBuilder;
import jenkins.model.Jenkins;
import okhttp3.OkHttpClient;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TuleapSecurityRealmTest {

    private PluginHelper pluginHelper;
    private AuthorizationCodeChecker authorizationCodeChecker;
    private AccessTokenChecker accessTokenChecker;
    private Gson gson;
    private IDTokenChecker IDTokenChecker;
    private OkHttpClient httpClient;
    private TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder;

    private Jenkins jenkins;

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelperImpl.class);
        this.authorizationCodeChecker = mock(AuthorizationCodeChecker.class);
        this.accessTokenChecker = mock(AccessTokenChecker.class);
        this.gson = mock(Gson.class);
        this.IDTokenChecker = mock(IDTokenChecker.class);
        this.httpClient = mock(OkHttpClient.class);
        this.authorizationCodeUrlBuilder = mock(TuleapAuthorizationCodeUrlBuilder.class);

        this.jenkins = mock(Jenkins.class);
        when(pluginHelper.getJenkinsInstance()).thenReturn(jenkins);
    }

    private void injectMock(TuleapSecurityRealm securityRealm) {
        securityRealm.setPluginHelper(this.pluginHelper);
        securityRealm.setAuthorizationCodeChecker(this.authorizationCodeChecker);
        securityRealm.setAccessTokenChecker(this.accessTokenChecker);
        securityRealm.setGson(this.gson);
        securityRealm.setIDTokenChecker(this.IDTokenChecker);
        securityRealm.setHttpClient(this.httpClient);
        securityRealm.setAuthorizationCodeUrlBuilder(this.authorizationCodeUrlBuilder);
    }

    @Test
    public void testAddDashAtTheEndOfTheTuleapUriWhenItIsMissing() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("https://jenkins.example.com", "", "");
        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    public void testItDoesNotAddADashAtTheOfTheUriIfTheUriAlreadyEndWithIt() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("https://jenkins.example.com/", "", "");
        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    public void testItShouldRedirectToClassicLogoutUrlWhenAnonymousUsersCanRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(true);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getPostLogOutUrl(request, authentication));
    }

    @Test
    public void testItShouldRedirectToTuleapLogoutUrlWhenAnonymousUsersCannotRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(false);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/tuleapLogout", tuleapSecurityRealm.getPostLogOutUrl(request, authentication));
    }

    @Test
    public void testTheValidationIsOkWhenTheClientIdIsValid() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("tlp-client-id-1"));
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("tlp-client-id-48488484"));
    }

    @Test
    public void testTheValidationIsNotOkWhenTheClientIdFormatIsNotValid() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(
            FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("tlp-client-id-fghhf").getMessage()
        );
        assertEquals(FormValidation.error(
            Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("freogjeuobnfb").getMessage()
        );
        assertEquals(FormValidation.error(
            Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("snv-tlp-client-id-10").getMessage()
        );
        assertEquals(FormValidation.error(
            Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("tlp-id-10").getMessage()
        );

        assertEquals(FormValidation.error(
            Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("tlp-client-id-").getMessage()
        );
    }

    @Test
    public void testTheValidationIsNotOkWhenTheClientIdIsEmpty() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(FormValidation.error(
            Messages.TuleapSecurityRealmDescriptor_CheckClientIdEmpty()).getMessage(),
            descriptor.doCheckClientId("").getMessage()
        );
    }
}
