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
import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.core.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.rest.RestRequest.Method.GET;
import static com.colasoft.opensearch.rest.RestRequest.Method.POST;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class DashboardsInfoAction extends BaseRestHandler {

    private static final List<Route> routes = ImmutableList.<Route>builder()
        .addAll(addRoutesPrefix(
            ImmutableList.of(
                new Route(GET, "/dashboardsinfo"),
                new Route(POST, "/dashboardsinfo")
            ),
            "/_plugins/_security"))
        .addAll(addRoutesPrefix(
            ImmutableList.of(
                new Route(GET, "/kibanainfo"),
                new Route(POST, "/kibanainfo")
            ),
            "/_opendistro/_security"))
        .build();

    private final Logger log = LogManager.getLogger(this.getClass());
    private final PrivilegesEvaluator evaluator;
    private final ThreadContext threadContext;

    public DashboardsInfoAction(final Settings settings, final RestController controller, final PrivilegesEvaluator evaluator, final ThreadPool threadPool) {
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
                    
                    final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

                    builder.startObject();
                    builder.field("user_name", user==null?null:user.getName());
                    builder.field("not_fail_on_forbidden_enabled", evaluator.notFailOnForbiddenEnabled());
                    builder.field("opensearch_dashboards_mt_enabled", evaluator.multitenancyEnabled());
                    builder.field("opensearch_dashboards_index", evaluator.dashboardsIndex());
                    builder.field("opensearch_dashboards_server_user", evaluator.dashboardsServerUsername());
                    builder.field("multitenancy_enabled", evaluator.multitenancyEnabled());
                    builder.field("private_tenant_enabled", evaluator.privateTenantEnabled());
                    builder.field("default_tenant", evaluator.dashboardsDefaultTenant());
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
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

    @Override
    public String getName() {
        return "Kibana Info Action";
    }
    
    
}
