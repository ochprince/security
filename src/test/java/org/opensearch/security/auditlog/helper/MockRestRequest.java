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

package com.colasoft.opensearch.security.auditlog.helper;

import java.util.Collections;

import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.rest.RestRequest;

public class MockRestRequest extends RestRequest {

    public MockRestRequest() {
        //NamedXContentRegistry xContentRegistry, Map<String, String> params, String path,
        //Map<String, List<String>> headers, HttpRequest httpRequest, HttpChannel httpChannel
        super(NamedXContentRegistry.EMPTY, Collections.emptyMap(), "", Collections.emptyMap(), null, null);
    }

    @Override
    public Method method() {
        return Method.GET;
    }

    @Override
    public String uri() {
        return "";
    }

    @Override
    public boolean hasContent() {
        return false;
    }

    @Override
    public BytesReference content() {
        return null;
    }
}
