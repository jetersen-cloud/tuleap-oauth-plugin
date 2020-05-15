package io.jenkins.plugins.tuleap_oauth;

import hudson.model.User;
import hudson.util.Secret;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import java.util.Objects;

import static org.junit.Assert.*;

public class TuleapAccessTokenStorageTest {
    private final TuleapAccessTokenStorage tuleapAccessTokenStorage = new TuleapAccessTokenStorage();

    @Rule
    public RestartableJenkinsRule j = new RestartableJenkinsRule();

    @Test
    public void correctBehavior() throws Exception {
        j.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                User.getById("alice", true);
                final String tuleapAccessToken = "This is a very important secret";

                assertFalse(tuleapAccessTokenStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                assertNull(tuleapAccessTokenStorage.retrieve(Objects.requireNonNull(User.getById("alice", false))));

                tuleapAccessTokenStorage.save(Objects.requireNonNull(User.getById("alice", false)), Secret.fromString(tuleapAccessToken));

                assertTrue(tuleapAccessTokenStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                assertEquals(tuleapAccessToken, tuleapAccessTokenStorage.retrieve(Objects.requireNonNull(User.getById("alice", false))).getPlainText());
            }
        });
    }

    @Test
    public void correctBehaviorEvenAfterRestart() throws Exception {
        final String tuleapAccessToken = "This is a very important secret";

        j.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                User.getById("alice", true).save();

                assertFalse(tuleapAccessTokenStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                assertNull(tuleapAccessTokenStorage.retrieve(Objects.requireNonNull(User.getById("alice", false))));

                tuleapAccessTokenStorage.save(Objects.requireNonNull(User.getById("alice", false)), Secret.fromString(tuleapAccessToken));

                assertTrue(tuleapAccessTokenStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                assertEquals(tuleapAccessToken, tuleapAccessTokenStorage.retrieve(Objects.requireNonNull(User.getById("alice", false))).getPlainText());
            }
        });
        j.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                assertTrue(tuleapAccessTokenStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                assertEquals(tuleapAccessToken, tuleapAccessTokenStorage.retrieve(Objects.requireNonNull(User.getById("alice", false))).getPlainText());
            }
        });
    }
}
