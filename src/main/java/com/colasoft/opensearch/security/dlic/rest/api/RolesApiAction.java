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

import java.nio.file.Path;
import java.util.List;

import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.RolesValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class RolesApiAction extends PatchableResourceApiAction {
	private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
			new Route(Method.GET, "/roles/"),
			new Route(Method.GET, "/roles/{name}"),
			new Route(Method.DELETE, "/roles/{name}"),
			new Route(Method.PUT, "/roles/{name}"),
			new Route(Method.PATCH, "/roles/"),
			new Route(Method.PATCH, "/roles/{name}")
	));

	@Inject
	public RolesApiAction(Settings settings, final Path configPath, RestController controller, Client client, AdminDNs adminDNs, ConfigurationRepository cl,
                          ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ROLES;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new RolesValidator(request, isSuperAdmin(), ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "role";
	}

	@Override
    protected CType getConfigName() {
        return CType.ROLES;
	}

}
