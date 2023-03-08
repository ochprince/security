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

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.action.index.IndexResponse;
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
import com.colasoft.opensearch.security.dlic.rest.validation.RolesMappingValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesMappingApiAction extends PatchableResourceApiAction {
	private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
			new Route(Method.GET, "/rolesmapping/"),
			new Route(Method.GET, "/rolesmapping/{name}"),
			new Route(Method.DELETE, "/rolesmapping/{name}"),
			new Route(Method.PUT, "/rolesmapping/{name}"),
			new Route(Method.PATCH, "/rolesmapping/"),
			new Route(Method.PATCH, "/rolesmapping/{name}")
	));

	@Inject
	public RolesMappingApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                                 final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                                 final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(getConfigName(), false);
		final boolean rolesMappingExists = rolesMappingConfiguration.exists(name);

		if (!isValidRolesMapping(channel, name)) return;

		rolesMappingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, rolesMappingConfiguration.getImplementingClass()));

		saveAnUpdateConfigs(client, request, getConfigName(), rolesMappingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

			@Override
			public void onResponse(IndexResponse response) {
				if (rolesMappingExists) {
					successResponse(channel, "'" + name + "' updated.");
				} else {
					createdResponse(channel, "'" + name + "' created.");
				}

			}
		});
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ROLESMAPPING;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new RolesMappingValidator(request, isSuperAdmin(), ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "rolesmapping";
	}

	@Override
    protected CType getConfigName() {
        return CType.ROLESMAPPING;
	}

}
