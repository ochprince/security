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
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.security.DefaultObjectMapper;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.ActionGroupValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ActionGroupsApiAction extends PatchableResourceApiAction {

	private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
			// legacy mapping for backwards compatibility
			// TODO: remove in next version
			new Route(Method.GET, "/actiongroup/{name}"),
			new Route(Method.GET, "/actiongroup/"),
			new Route(Method.DELETE, "/actiongroup/{name}"),
			new Route(Method.PUT, "/actiongroup/{name}"),

			// corrected mapping, introduced in OpenSearch Security
			new Route(Method.GET, "/actiongroups/{name}"),
			new Route(Method.GET, "/actiongroups/"),
			new Route(Method.DELETE, "/actiongroups/{name}"),
			new Route(Method.PUT, "/actiongroups/{name}"),
			new Route(Method.PATCH, "/actiongroups/"),
			new Route(Method.PATCH, "/actiongroups/{name}")

	));

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ACTIONGROUPS;
	}

	@Inject
	public ActionGroupsApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                                 final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                                 final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(final RestRequest request, BytesReference ref, Object... param) {
		return new ActionGroupValidator(request, isSuperAdmin(), ref, this.settings, param);
	}

	@Override
	protected CType getConfigName() {
		return CType.ACTIONGROUPS;
	}

	@Override
    protected String getResourceName() {
        return "actiongroup";
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("name");
	}

	@Override
	protected void handlePut(RestChannel channel, RestRequest request, Client client, JsonNode content) throws IOException {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		// Prevent the case where action group and role share a same name.
		SecurityDynamicConfiguration<?> existingRolesConfig = load(CType.ROLES, false);
		Set<String> existingRoles = existingRolesConfig.getCEntries().keySet();
		if (existingRoles.contains(name)) {
			badRequestResponse(channel, name + " is an existing role. A action group cannot be named with an existing role name.");
			return;
		}

		// Prevent the case where action group references to itself in the allowed_actions.
		final SecurityDynamicConfiguration<?> existingActionGroupsConfig = load(getConfigName(), false);
		existingActionGroupsConfig.putCObject(name, DefaultObjectMapper.readTree(content, existingActionGroupsConfig.getImplementingClass()));
		if (hasActionGroupSelfReference(existingActionGroupsConfig, name)) {
			badRequestResponse(channel, name + " cannot be an allowed_action of itself");
			return;
		}

		super.handlePut(channel, request, client, content);
	}
}
