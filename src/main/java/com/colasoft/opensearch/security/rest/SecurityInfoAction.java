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
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.RamUsageEstimator;

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.transport.TransportAddress;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.common.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.support.Base64Helper;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.rest.RestRequest.Method.GET;
import static com.colasoft.opensearch.rest.RestRequest.Method.POST;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class SecurityInfoAction extends BaseRestHandler {
    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(GET, "/authinfo"),
            new Route(POST, "/authinfo")
    ),"/_opendistro/_security", "/_plugins/_security");

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;

    public SecurityInfoAction(final Settings settings, final RestController controller, final PrivilegesEvaluator evaluator, final ThreadPool threadPool) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.evaluator = evaluator;
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

                    
                    final boolean verbose = request.paramAsBoolean("verbose", false);
                    
                    final X509Certificate[] certs = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PEER_CERTIFICATES);
                    final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    final TransportAddress remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

                    final Set<String> securityRoles = evaluator.mapRoles(user, remoteAddress);

                    builder.startObject();
                    builder.field("user", user==null?null:user.toString());
                    builder.field("user_name", user==null?null:user.getName());
                    builder.field("user_requested_tenant", user==null?null:user.getRequestedTenant());
                    builder.field("remote_address", remoteAddress);
                    builder.field("backend_roles", user==null?null:user.getRoles());
                    builder.field("custom_attribute_names", user==null?null:user.getCustomAttributesMap().keySet());
                    builder.field("roles", securityRoles);
                    builder.field("tenants", evaluator.mapTenants(user, securityRoles));
                    builder.field("principal", (String)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL));
                    builder.field("peer_certificates", certs != null && certs.length > 0 ? certs.length + "" : "0");
                    builder.field("sso_logout_url", (String)threadContext.getTransient(ConfigConstants.SSO_LOGOUT_URL));
                    
                    if(user != null && verbose) {
                        try {
                            builder.field("size_of_user", RamUsageEstimator.humanReadableUnits(Base64Helper.serializeObject(user).length()));
                            builder.field("size_of_custom_attributes", RamUsageEstimator.humanReadableUnits(Base64Helper.serializeObject((Serializable) user.getCustomAttributesMap()).getBytes(StandardCharsets.UTF_8).length));
                            builder.field("size_of_backendroles", RamUsageEstimator.humanReadableUnits(Base64Helper.serializeObject((Serializable)user.getRoles()).getBytes(StandardCharsets.UTF_8).length));
                        } catch (Throwable e) {
                            //ignore
                        }
                    }
                    
                    
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    log.error(e1.toString(),e1);
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
    
    @Override
    public String getName() {
        return "OpenSearch Security Info Action";
    }
}
