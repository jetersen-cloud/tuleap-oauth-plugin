package io.jenkins.plugins.tuleap_oauth;

import hudson.model.User;
import hudson.util.Secret;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TuleapAccessTokenStorage {
    private final Logger LOGGER =  Logger.getLogger(TuleapAccessTokenStorage.class.getName());

    public void save(User user, Secret accessToken) {
        try {
            user.addProperty(new TuleapAccessTokenProperty(accessToken));
        } catch (IOException exception) {
            LOGGER.log(Level.WARNING, "Error while trying to save user acces token for user: " + user.getId(), exception);
        }
    }

    public boolean has(User user) {
        return user.getProperty(TuleapAccessTokenProperty.class) != null;
    }

    public Secret retrieve(User user) {
        TuleapAccessTokenProperty tokenProperty = user.getProperty(TuleapAccessTokenProperty.class);

        if (tokenProperty == null) {
            return null;
        } else {
            return tokenProperty.getAccessToken();
        }
    }
}
