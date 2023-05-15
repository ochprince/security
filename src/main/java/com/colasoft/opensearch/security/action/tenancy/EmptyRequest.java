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

package com.colasoft.opensearch.security.action.tenancy;

import java.io.IOException;

import com.colasoft.opensearch.action.ActionRequest;
import com.colasoft.opensearch.action.ActionRequestValidationException;
import com.colasoft.opensearch.common.io.stream.StreamInput;

public class EmptyRequest extends ActionRequest {

    public EmptyRequest(final StreamInput in) throws IOException {
        super(in);
    }

    public EmptyRequest() throws IOException {
        super();
    }

    @Override
    public ActionRequestValidationException validate()
    {
        return null;
    }
}
