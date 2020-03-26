package io.jenkins.plugins.tuleap_oauth;

import com.google.inject.Guice;
import com.google.inject.Injector;
import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.tuleap_oauth.guice.TuleapOAuth2GuiceModule;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;

import javax.annotation.CheckForNull;

@Extension
public class TuleapLogoutAction implements UnprotectedRootAction {

    static final String REDIRECT_ON_LOGOUT = "tuleapLogout";
    private PluginHelper pluginHelper;

    public TuleapLogoutAction(){
        Injector injector = Guice.createInjector(new TuleapOAuth2GuiceModule());
        this.pluginHelper = injector.getInstance(PluginHelper.class);
    }

    // For testing purpose
    public TuleapLogoutAction(PluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @CheckForNull
    @Override
    public String getIconFileName() {
        return null;
    }

    @CheckForNull
    @Override
    public String getDisplayName() {
        return "Tuleap logout";
    }

    @CheckForNull
    @Override
    public String getUrlName() {
        return REDIRECT_ON_LOGOUT;
    }

    public String getTuleapUrl() {
        SecurityRealm realm = this.pluginHelper.getJenkinsInstance().getSecurityRealm();
        if (realm instanceof TuleapSecurityRealm) {
            return ((TuleapSecurityRealm) realm).getTuleapUri();
        }
        return "";
    }
}
