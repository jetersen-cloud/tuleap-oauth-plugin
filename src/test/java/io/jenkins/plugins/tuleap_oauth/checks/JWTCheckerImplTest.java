package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_oauth.checks.exceptions.SessionExpiredException;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mockito;

import javax.servlet.http.HttpSession;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.*;

public class JWTCheckerImplTest {

    private PluginHelper pluginHelper;

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelper.class);
    }

    @Test(expected = InvalidClaimException.class)
    public void testHeaderThrowsExceptionWhenTheTypeIsNotExpected() {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getType()).thenReturn("JWGDLMGLD");

        jwtChecker.checkHeader(jwt);
    }

    @Test(expected = InvalidClaimException.class)
    public void testHeaderThrowsExceptionWhenTheAlgIsNotExpected() {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getType()).thenReturn("JWT");
        when(jwt.getAlgorithm()).thenReturn("HS256");

        jwtChecker.checkHeader(jwt);
    }

    @Test
    public void testHeaderIsOk() {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getType()).thenReturn("JWT");
        when(jwt.getAlgorithm()).thenReturn("RS256");

        jwtChecker.checkHeader(jwt);
    }

    @Test(expected = AlgorithmMismatchException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenTheAlgorithmIsNotExpected() throws InvalidPublicKeyException {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getIssuer()).thenReturn("https://success.example.com");
        when(jwt.getAlgorithm()).thenReturn("HS256");
        when(jwt.getAudience()).thenReturn(Collections.singletonList("B35S"));

        Claim nonceClaim = mock(Claim.class);
        when(nonceClaim.asString()).thenReturn("rgneighiohetogh");
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);

        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");

        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");

        List<Jwk> jwkList = Collections.singletonList(key1);

        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);

        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn("1234");
        when(request.getSession()).thenReturn(session);

        String issuer = "https://success.example.com";
        String audience = "B35S";
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, issuer, audience, request);
    }

    @Test(expected = InvalidClaimException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenNonceValueIsNotExpected() throws SessionExpiredException, InvalidPublicKeyException {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getIssuer()).thenReturn("https://success.example.com");
        when(jwt.getAlgorithm()).thenReturn("RS256");
        when(jwt.getAudience()).thenReturn(Collections.singletonList("B35S"));

        Claim nonceClaim = mock(Claim.class);
        when(nonceClaim.asString()).thenReturn("rgneighiohetogh");
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);

        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");

        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");

        List<Jwk> jwkList = Collections.singletonList(key1);

        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);

        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn("1234");
        when(request.getSession()).thenReturn(session);

        String issuer = "https://success.example.com";
        String audience = "B35S";
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, issuer, audience, request);
    }

    @Test(expected = InvalidPublicKeyException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenThereIsNoRS256ValidKey() throws SessionExpiredException, InvalidPublicKeyException {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getIssuer()).thenReturn("https://success.example.com");
        when(jwt.getAlgorithm()).thenReturn("RS256");
        when(jwt.getAudience()).thenReturn(Collections.singletonList("B35S"));

        Claim nonceClaim = mock(Claim.class);
        when(nonceClaim.asString()).thenReturn("1234");
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);

        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        doThrow(SignatureVerificationException.class).when(algorithmKey1).verify(jwt);
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");
        doThrow(SignatureVerificationException.class).when(algorithmKey2).verify(jwt);

        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        RSAPublicKey publicKey1 = mock(RSAPublicKey.class);
        when(key1.getPublicKey()).thenReturn(publicKey1);
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");

        List<Jwk> jwkList = Arrays.asList(key1, key2);

        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);

        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn("1234");
        when(request.getSession()).thenReturn(session);

        String issuer = "https://success.example.com/";
        String audience = "B35S";
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, issuer, audience, request);
    }

    @Test(expected = InvalidPublicKeyException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenThereIsNoRS256Key() throws SessionExpiredException, InvalidPublicKeyException {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getIssuer()).thenReturn("https://success.example.com");
        when(jwt.getAlgorithm()).thenReturn("RS256");
        when(jwt.getAudience()).thenReturn(Collections.singletonList("B35S"));

        Claim nonceClaim = mock(Claim.class);
        when(nonceClaim.asString()).thenReturn("1234");
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);

        Algorithm algorithmKey1 = mock(Algorithm.class);
        verify(algorithmKey1, never()).verify(jwt);
        Algorithm algorithmKey2 = mock(Algorithm.class);
        verify(algorithmKey2, never()).verify(jwt);

        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("HS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("HS256");

        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);

        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn("1234");
        when(request.getSession()).thenReturn(session);

        String issuer = "https://success.example.com/";
        String audience = "B35S";
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, issuer, audience, request);
    }

    @Test
    public void testPayloadAndSignatureAreOk() throws SessionExpiredException, InvalidPublicKeyException {
        JWTCheckerImpl jwtChecker = new JWTCheckerImpl(this.pluginHelper);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getIssuer()).thenReturn("https://success.example.com");
        when(jwt.getAlgorithm()).thenReturn("RS256");
        when(jwt.getAudience()).thenReturn(Collections.singletonList("B35S"));

        Claim nonceClaim = mock(Claim.class);
        when(nonceClaim.asString()).thenReturn("1234");
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);

        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");

        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");

        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);

        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn("1234");
        when(request.getSession()).thenReturn(session);

        String issuer = "https://success.example.com/";
        String audience = "B35S";
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, issuer, audience, request);
    }
}
