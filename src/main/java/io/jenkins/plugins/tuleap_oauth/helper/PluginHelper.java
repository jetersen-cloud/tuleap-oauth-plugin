package io.jenkins.plugins.tuleap_oauth.helper;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import jenkins.model.Jenkins;

public interface PluginHelper {
    Jenkins getJenkinsInstance();
    String buildRandomBase64EncodedURLSafeString();
    Algorithm getAlgorithm(Jwk jwk) throws InvalidPublicKeyException;
}
