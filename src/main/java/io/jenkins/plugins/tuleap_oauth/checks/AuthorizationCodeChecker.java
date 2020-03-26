package io.jenkins.plugins.tuleap_oauth.checks;

import org.kohsuke.stapler.StaplerRequest;

public interface AuthorizationCodeChecker {
    boolean checkAuthorizationCode(StaplerRequest request);
}
