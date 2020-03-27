package io.jenkins.plugins.tuleap_oauth.okhttp;

import com.google.inject.Inject;
import com.google.inject.Provider;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import jenkins.model.Jenkins;
import okhttp3.OkHttpClient;

import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class OkHttpClientProvider implements Provider<OkHttpClient> {
    private PluginHelper pluginHelper;

    @Inject
    public OkHttpClientProvider(PluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @Override
    public OkHttpClient get() {
        return new OkHttpClient
            .Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .cache(null)
            .proxy(getProxy(getTuleapHost()))
            .build();
    }

    private String getTuleapHost() {
        SecurityRealm realm = this.pluginHelper.getJenkinsInstance().getSecurityRealm();
        if (!(realm instanceof TuleapSecurityRealm)) {
            return "";
        }
        String uri = ((TuleapSecurityRealm) realm).getTuleapUri();
        try {
            return new URL(uri).getHost();
        } catch (MalformedURLException exception) {
            throw new RuntimeException(exception);
        }
    }

    private Proxy getProxy(String host) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();

        if (jenkins == null || jenkins.proxy == null) {
            return Proxy.NO_PROXY;
        } else {
            return jenkins.proxy.createProxy(host);
        }
    }
}
