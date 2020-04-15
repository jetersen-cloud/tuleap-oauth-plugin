package io.jenkins.plugins.tuleap_oauth.helper;

import jenkins.model.Jenkins;
import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;

public class PluginHelperImpl implements PluginHelper {
    public Jenkins getJenkinsInstance() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        return jenkins;
    }

    public String buildRandomBase64EncodedURLSafeString(final int byteLength) {
        byte[] code = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(code);
        return Base64.encodeBase64URLSafeString(code);
    }
}
