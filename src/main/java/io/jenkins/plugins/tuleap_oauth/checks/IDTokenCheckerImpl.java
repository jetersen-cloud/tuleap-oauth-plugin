package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.model.TuleapOpenIdConfigurationRepresentation;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.util.List;

public class IDTokenCheckerImpl implements IDTokenChecker {

    public static final String ALGORITHM = "RS256";

    private static final int ACCEPTED_LEEWAY_IN_SECONDS = 10;

    private static final String DISCOVERY_ENDPOINT = ".well-known/openid-configuration";

    private PluginHelper pluginHelper;
    private OkHttpClient okHttpClient;
    private Gson gson;

    @Inject
    public IDTokenCheckerImpl(PluginHelper pluginHelper, OkHttpClient okHttpClient, Gson gson) {
        this.pluginHelper = pluginHelper;
        this.okHttpClient = okHttpClient;
        this.gson = gson;
    }

    @Override
    public void checkHeader(DecodedJWT jwt) {
        if (!jwt.getType().equals("JWT")) {
            throw new InvalidClaimException("The Claim 'typ' value doesn't match the required one");
        }

        if (!jwt.getAlgorithm().equals(ALGORITHM)) {
            throw new InvalidClaimException("The Claim 'alg' value doesn't match the required one");
        }
    }

    @Override
    public void checkPayloadAndSignature(
        DecodedJWT idToken,
        List<Jwk> jwks,
        String tuleapUri,
        String audience,
        StaplerRequest request
    ) throws InvalidPublicKeyException, IOException {
        String expectedIssuer = this.getIssuer(tuleapUri);

        if (StringUtils.isBlank(expectedIssuer)) {
            throw new InvalidClaimException("The issuer claim is blank or null");
        }

        String expectedNonce = (String) request.getSession().getAttribute(TuleapSecurityRealm.NONCE_ATTRIBUTE);

        for (Jwk jwk : jwks) {
            if (jwk.getAlgorithm().equals(ALGORITHM)) {
                try {
                    Algorithm algorithm = this.pluginHelper.getAlgorithm(jwk);
                    JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer(expectedIssuer)
                        .withAudience(audience)
                        .acceptLeeway(ACCEPTED_LEEWAY_IN_SECONDS)
                        .withClaim(TuleapSecurityRealm.NONCE_ATTRIBUTE, expectedNonce)
                        .build();

                    if (StringUtils.isBlank(audience)) {
                        throw new InvalidClaimException("The audience claim is blank or null");
                    }

                    verifier.verify(idToken);
                    return;
                } catch (SignatureVerificationException | InvalidPublicKeyException e) {
                    //The key does not match
                }
            }
        }
        throw new InvalidPublicKeyException("No valid RS256 Key found", null);
    }

    private String getIssuer(String tuleapUri) throws IOException {
        Request req = new Request.Builder()
            .url(tuleapUri + DISCOVERY_ENDPOINT)
            .get()
            .build();

        TuleapOpenIdConfigurationRepresentation configuration;
        try (Response issuerResponse = this.okHttpClient.newCall(req).execute()) {
            ResponseBody body = this.pluginHelper.getResponseBody(issuerResponse);
            if (body == null) {
                return null;
            }
            configuration = this.gson.fromJson(body.string(), TuleapOpenIdConfigurationRepresentation.class);
        }
        return configuration.getIssuer();
    }
}
