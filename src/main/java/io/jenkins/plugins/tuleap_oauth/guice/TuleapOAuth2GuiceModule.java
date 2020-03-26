package io.jenkins.plugins.tuleap_oauth.guice;

import com.google.inject.AbstractModule;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeCheckerImpl;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelperImpl;

public class TuleapOAuth2GuiceModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(AuthorizationCodeChecker.class).to(AuthorizationCodeCheckerImpl.class);
        bind(PluginHelper.class).to(PluginHelperImpl.class);
    }
}
