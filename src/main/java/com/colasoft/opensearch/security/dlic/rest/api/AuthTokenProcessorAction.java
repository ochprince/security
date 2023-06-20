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

package com.colasoft.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.NoOpValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class AuthTokenProcessorAction extends AbstractApiAction {
	private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(
			new Route(Method.POST, "/authtoken")
	));

	@Inject
	public AuthTokenProcessorAction(final Settings settings, final Path configPath, final RestController controller,
                                    final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
                                    final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
                                    ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
				auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {

		// Just do nothing here. Eligible authenticators will intercept calls and
		// provide own responses.
	    successResponse(channel,"");
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "authtoken";
	}

	@Override
    protected CType getConfigName() {
		return null;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.AUTHTOKEN;
	}


	public static class Response {
		private String authorization;

		public String getAuthorization() {
			return authorization;
		}

		public void setAuthorization(String authorization) {
			this.authorization = authorization;
		}
	}
}
