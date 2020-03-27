package io.jenkins.plugins.tuleap_oauth.checks;

import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;

public interface AccessTokenChecker {
    boolean checkResponseHeader(Response response);
    boolean checkResponseBody(ResponseBody body) throws IOException;
}
