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
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.transport.TransportAddress;
import com.colasoft.opensearch.core.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Provides the evaluated REST API permissions for the currently logged in user
 */
public class PermissionsInfoAction extends BaseRestHandler {
	private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(
			new Route(Method.GET, "/permissionsinfo")
	));

	private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
	private final ThreadPool threadPool;
	private final PrivilegesEvaluator privilegesEvaluator;
	private final ConfigurationRepository configurationRepository;

	protected PermissionsInfoAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                                    final AdminDNs adminDNs, final ConfigurationRepository configurationRepository, final ClusterService cs,
                                    final PrincipalExtractor principalExtractor, final PrivilegesEvaluator privilegesEvaluator, ThreadPool threadPool, AuditLog auditLog) {
		super();
		this.threadPool = threadPool;
		this.privilegesEvaluator = privilegesEvaluator;
		this.restApiPrivilegesEvaluator = new RestApiPrivilegesEvaluator(settings, adminDNs, privilegesEvaluator, principalExtractor, configPath, threadPool);
		this.configurationRepository = configurationRepository;
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	@Override
	public List<Route> routes() {
		return routes;
	}

	@Override
	protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
		switch (request.method()) {
		case GET:
			return handleGet(request, client);
		default:
			throw new IllegalArgumentException(request.method() + " not supported");
		}
	}

	private RestChannelConsumer handleGet(RestRequest request, NodeClient client) throws IOException {

        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder(); //NOSONAR
                BytesRestResponse response = null;

                try {

            		final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            		final TransportAddress remoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
            		Set<String> userRoles = privilegesEvaluator.mapRoles(user, remoteAddress);
            		Boolean hasApiAccess = restApiPrivilegesEvaluator.currentUserHasRestApiAccess(userRoles);
            		Map<Endpoint, List<Method>> disabledEndpoints = restApiPrivilegesEvaluator.getDisabledEndpointsForCurrentUser(user.getName(), userRoles);
            		if (!configurationRepository.isAuditHotReloadingEnabled()) {
            		   disabledEndpoints.put(Endpoint.AUDIT, ImmutableList.copyOf(Method.values()));
            		}

                    builder.startObject();
                    builder.field("user", user==null?null:user.toString());
                    builder.field("user_name", user==null?null:user.getName()); //NOSONAR
                    builder.field("has_api_access", hasApiAccess);
                    builder.startObject("disabled_endpoints");
                    for(Entry<Endpoint, List<Method>>  entry : disabledEndpoints.entrySet()) {
                    	builder.field(entry.getKey().name(), entry.getValue());
                    }
                    builder.endObject();
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    e1.printStackTrace();
                    builder = channel.newBuilder(); //NOSONAR
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if(builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };

	}

}
