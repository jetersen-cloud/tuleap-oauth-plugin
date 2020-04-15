package io.jenkins.plugins.tuleap_oauth.helper;

import jenkins.model.Jenkins;

public interface PluginHelper {
    Jenkins getJenkinsInstance();
    String buildRandomBase64EncodedURLSafeString(final int byteLength);
}
