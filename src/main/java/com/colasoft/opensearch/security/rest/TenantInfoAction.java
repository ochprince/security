/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ColaSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

package com.colasoft.opensearch.security.rest;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.SortedMap;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.cluster.metadata.IndexAbstraction;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.core.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.DynamicConfigFactory;
import com.colasoft.opensearch.security.securityconf.RoleMappings;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.rest.RestRequest.Method.GET;
import static com.colasoft.opensearch.rest.RestRequest.Method.POST;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class TenantInfoAction extends BaseRestHandler {
    private static final List<Route> routes = addRoutesPrefix(
            ImmutableList.of(
                new Route(GET, "/tenantinfo"),
                new Route(POST, "/tenantinfo")
            ),
            "/_opendistro/_security", "/_plugins/_security");

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;
    private final ClusterService clusterService;
    private final AdminDNs adminDns;
    private final ConfigurationRepository configurationRepository;

    public TenantInfoAction(final Settings settings, final RestController controller, 
    		final PrivilegesEvaluator evaluator, final ThreadPool threadPool, final ClusterService clusterService, final AdminDNs adminDns,
                            final ConfigurationRepository configurationRepository) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
        this.clusterService = clusterService;
        this.adminDns = adminDns;
        this.configurationRepository = configurationRepository;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder(); //NOSONAR
                BytesRestResponse response = null;
                
                try {

                    final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    
                    //only allowed for admins or the kibanaserveruser
                    if(!isAuthorized()) {
                        response = new BytesRestResponse(RestStatus.FORBIDDEN,"");
                    } else {

                    	builder.startObject();
	
                    	final SortedMap<String, IndexAbstraction> lookup = clusterService.state().metadata().getIndicesLookup();
                    	for(final String indexOrAlias: lookup.keySet()) {
                    		final String tenant = tenantNameForIndex(indexOrAlias);
                    		if(tenant != null) {
                    			builder.field(indexOrAlias, tenant);
                    		}
                    	}

	                    builder.endObject();
	
	                    response = new BytesRestResponse(RestStatus.OK, builder);
                    }
                } catch (final Exception e1) {
                    log.error(e1.toString());
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

    private boolean isAuthorized() {
        final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        if (user == null) {
            return false;
        }

        // check if the user is a kibanauser or super admin
        if (user.getName().equals(evaluator.dashboardsServerUsername()) || adminDns.isAdmin(user)) {
            return true;
        }

        // If user check failed by name and admin, check if the users belong to dashboards role
        final SecurityDynamicConfiguration<?> rolesMappingConfiguration = load(CType.ROLESMAPPING, true);

        // check if dashboardsOpenSearchRole is present in RolesMapping and if yes, check if user is a part of this role
        if (rolesMappingConfiguration != null) {
            String dashboardsOpenSearchRole = evaluator.dashboardsOpenSearchRole();
            if (Strings.isNullOrEmpty(dashboardsOpenSearchRole)) {
                return false;
            }
            RoleMappings roleMapping = (RoleMappings) rolesMappingConfiguration.getCEntries().getOrDefault(dashboardsOpenSearchRole, null);
            return roleMapping != null && roleMapping.getUsers().contains(user.getName());
        }

        return false;
    }

    private final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
        SecurityDynamicConfiguration<?> loaded = configurationRepository.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent).get(config).deepClone();
        return DynamicConfigFactory.addStatics(loaded);
    }

    private String tenantNameForIndex(String index) {
    	String[] indexParts;
    	if(index == null 
    			|| (indexParts = index.split("_")).length != 3
    			) {
    		return null;
    	}
    	
    	
    	if(!indexParts[0].equals(evaluator.dashboardsIndex())) {
    		return null;
    	}
    	
    	try {
			final int expectedHash = Integer.parseInt(indexParts[1]);
			final String sanitizedName = indexParts[2];
			
			for(String tenant: evaluator.getAllConfiguredTenantNames()) {
				if(tenant.hashCode() == expectedHash && sanitizedName.equals(tenant.toLowerCase().replaceAll("[^a-z0-9]+",""))) {
					return tenant;
				}
			}

			return "__private__";
		} catch (NumberFormatException e) {
			log.warn("Index {} looks like a Security tenant index but we cannot parse the hashcode so we ignore it.", index);
			return null;
		}
    }

    @Override
    public String getName() {
        return "Tenant Info Action";
    }
    
    
}
