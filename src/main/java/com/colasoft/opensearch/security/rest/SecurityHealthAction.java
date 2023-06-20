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

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.core.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.auth.BackendRegistry;

import static com.colasoft.opensearch.rest.RestRequest.Method.GET;
import static com.colasoft.opensearch.rest.RestRequest.Method.POST;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class SecurityHealthAction extends BaseRestHandler {
    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(GET, "/health"),
            new Route(POST, "/health")
    ), "/_opendistro/_security", "/_plugins/_security");

    private final BackendRegistry registry;

    public SecurityHealthAction(final Settings settings, final RestController controller, final BackendRegistry registry) {
        super();
        this.registry = registry;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            
            final String mode = request.param("mode","strict");

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                RestStatus restStatus = RestStatus.OK;
                BytesRestResponse response = null;
                try {
                    
                    
                    String status = "UP";
                    String message = null;

                    builder.startObject();

                    if ("strict".equalsIgnoreCase(mode) && registry.isInitialized() == false) {
                        status = "DOWN";
                        message = "Not initialized";
                        restStatus = RestStatus.SERVICE_UNAVAILABLE;
                    }

                    builder.field("message", message);
                    builder.field("mode", mode);
                    builder.field("status", status);
                    builder.endObject();
                    response = new BytesRestResponse(restStatus, builder);

                } finally {
                    builder.close();
                }
                
                
                channel.sendResponse(response);
            }
            
            
        };
    }

    @Override
    public String getName() {
        return "OpenSearch Security Health Check";
    }

}
