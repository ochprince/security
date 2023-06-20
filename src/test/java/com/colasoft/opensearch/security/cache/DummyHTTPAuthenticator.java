/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ColaSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package com.colasoft.opensearch.security.cache;

import java.nio.file.Path;

import com.colasoft.opensearch.OpenSearchSecurityException;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.security.auth.HTTPAuthenticator;
import com.colasoft.opensearch.security.user.AuthCredentials;

public class DummyHTTPAuthenticator implements HTTPAuthenticator {

    private static volatile long count;

    public DummyHTTPAuthenticator(final Settings settings, final Path configPath) {
    }

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public AuthCredentials extractCredentials(RestRequest request, ThreadContext context) throws OpenSearchSecurityException {
        count++;
        return new AuthCredentials("dummy").markComplete();
    }

    @Override
    public boolean reRequestAuthentication(RestChannel channel, AuthCredentials credentials) {
        return false;
    }

    public static long getCount() {
        return count;
    }

    public static void reset() {
        count=0;
    }
}
