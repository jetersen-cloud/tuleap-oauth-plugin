package io.jenkins.plugins.tuleap_oauth.helper;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import static org.junit.Assert.*;

public class PluginHelperImplTest {

    @Test
    public void testItShouldReturnARandomStringInBase64() {
        final PluginHelperImpl codeBuilder = new PluginHelperImpl();
        final String result1 = codeBuilder.buildRandomBase64EncodedURLSafeString();
        final String result2 = codeBuilder.buildRandomBase64EncodedURLSafeString();

        assertTrue(Base64.isBase64(result1));
        assertTrue(Base64.isBase64(result2));
        assertNotEquals(result1, result2);
    }

    @Test
    public void itShouldGenerateA43BytesLongSequence() {
        final PluginHelperImpl codeBuilder = new PluginHelperImpl();

        assertEquals(43, codeBuilder.buildRandomBase64EncodedURLSafeString().getBytes().length);
    }
}
