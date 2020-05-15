package io.jenkins.plugins.tuleap_oauth;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.util.Secret;
import org.jenkinsci.Symbol;

public class TuleapAccessTokenProperty extends UserProperty {
    private final Secret accessToken;

    public TuleapAccessTokenProperty(Secret accessToken) {
        this.accessToken = accessToken;
    }

    public Secret getAccessToken() {
        return accessToken;
    }

    @Extension
    @Symbol("tuleapAccessToken")
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public boolean isEnabled() {
            return false;
        }

        public UserProperty newInstance(User user) {
            return null;
        }
    }
}
