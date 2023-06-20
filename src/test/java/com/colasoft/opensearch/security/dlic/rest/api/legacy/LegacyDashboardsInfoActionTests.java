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

package com.colasoft.opensearch.security.dlic.rest.api.legacy;

import com.colasoft.opensearch.security.dlic.rest.api.DashboardsInfoActionTest;

import static com.colasoft.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;

public class LegacyDashboardsInfoActionTests extends DashboardsInfoActionTest {
	@Override
    protected String getEndpoint() {
        return LEGACY_OPENDISTRO_PREFIX + "/kibanainfo";
    }
}
