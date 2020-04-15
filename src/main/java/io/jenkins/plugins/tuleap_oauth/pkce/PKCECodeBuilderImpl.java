package io.jenkins.plugins.tuleap_oauth.pkce;

import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PKCECodeBuilderImpl implements PKCECodeBuilder {
    private final static Integer RFC_CODE_VERIFIER_RECOMMENDED_LENGTH = 32;

    private PluginHelper pluginHelper;

    @Inject
    public PKCECodeBuilderImpl(PluginHelper pluginHelper){
        this.pluginHelper = pluginHelper;
    }

    @Override
    public String buildCodeVerifier() {
        return this.pluginHelper.buildRandomBase64EncodedURLSafeString(RFC_CODE_VERIFIER_RECOMMENDED_LENGTH);
    }

    @Override
    public String buildCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] codeVerifierBytesASCII = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(codeVerifierBytesASCII);
        byte[] digest = messageDigest.digest();
        return Base64.encodeBase64URLSafeString(digest);
    }
}
