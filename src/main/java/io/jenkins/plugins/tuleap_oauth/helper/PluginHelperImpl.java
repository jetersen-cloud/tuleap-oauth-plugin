package io.jenkins.plugins.tuleap_oauth.helper;

import jenkins.model.Jenkins;

public class PluginHelperImpl implements PluginHelper {
    public Jenkins getJenkinsInstance() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        return jenkins;
    }
}
