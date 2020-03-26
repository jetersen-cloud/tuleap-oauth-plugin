package io.jenkins.plugins.tuleap_oauth;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;

import javax.annotation.CheckForNull;

@Extension
public class TuleapAuthenticationErrorAction implements UnprotectedRootAction {

    static final String REDIRECT_ON_AUTHENTICATION_ERROR = "tuleapError";

    @CheckForNull
    @Override
    public String getIconFileName() {
        return null;
    }

    @CheckForNull
    @Override
    public String getDisplayName() {
        return "Tuleap authentication error";
    }

    @CheckForNull
    @Override
    public String getUrlName() {
        return REDIRECT_ON_AUTHENTICATION_ERROR;
    }
}
