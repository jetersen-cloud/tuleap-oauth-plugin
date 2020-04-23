package io.jenkins.plugins.tuleap_oauth.helper;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import jenkins.model.Jenkins;
import org.apache.commons.net.util.Base64;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

public class PluginHelperImpl implements PluginHelper {

    private final static Integer RECOMMENDED_LENGTH = 32;

    public Jenkins getJenkinsInstance() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        return jenkins;
    }

    public String buildRandomBase64EncodedURLSafeString() {
        byte[] code = new byte[RECOMMENDED_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(code);
        return Base64.encodeBase64URLSafeString(code);
    }

    @Override
    public Algorithm getAlgorithm(Jwk jwk) throws InvalidPublicKeyException {
        return Algorithm.RSA256((RSAPublicKey)jwk.getPublicKey(),null);
    }
}
