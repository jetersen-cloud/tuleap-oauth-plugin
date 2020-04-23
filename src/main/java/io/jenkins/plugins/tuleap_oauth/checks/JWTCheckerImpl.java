package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import org.kohsuke.stapler.StaplerRequest;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.logging.Logger;

public class JWTCheckerImpl implements JWTChecker {

    public static final String ALGORITHM = "RS256";

    private static final int ISSUE_AT_LEEWAY = 60;

    private PluginHelper pluginHelper;

    @Inject
     public JWTCheckerImpl(PluginHelper pluginHelper){
        this.pluginHelper = pluginHelper;
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
    public void checkPayloadAndSignature(DecodedJWT jwt, List<Jwk> jwks, String issuer, String audience, StaplerRequest request) throws InvalidPublicKeyException {
        String expectedIssuer = issuer;
        if (expectedIssuer.endsWith("/")) {
            expectedIssuer = expectedIssuer.substring(0, expectedIssuer.length() - 1);
        }

        String expectedNonce = (String) request.getSession().getAttribute(TuleapSecurityRealm.NONCE_ATTRIBUTE);

        for (Jwk jwk : jwks) {
            if (jwk.getAlgorithm().equals(ALGORITHM)) {
                try {
                Algorithm algorithm = this.pluginHelper.getAlgorithm(jwk);
                JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(expectedIssuer)
                    .withAudience(audience)
                    .acceptIssuedAt(ISSUE_AT_LEEWAY)
                    .withClaim(TuleapSecurityRealm.NONCE_ATTRIBUTE, expectedNonce)
                    .build();

                    verifier.verify(jwt);
                    return;
                } catch (SignatureVerificationException | InvalidPublicKeyException e) {
                    //The key does not match
                }
            }
        }
        throw new InvalidPublicKeyException("No valid RS256 Key found", null);
    }
}
