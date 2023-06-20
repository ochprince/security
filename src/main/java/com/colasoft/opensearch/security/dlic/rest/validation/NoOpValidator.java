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

package com.colasoft.opensearch.security.dlic.rest.validation;

import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestRequest;

public class NoOpValidator extends AbstractConfigurationValidator {

	public NoOpValidator(final RestRequest request, BytesReference ref, final Settings opensearchSettings, Object... param) {
		super(request, ref, opensearchSettings, param);
	}

}
