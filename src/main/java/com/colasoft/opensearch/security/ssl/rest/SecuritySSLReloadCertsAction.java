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

package com.colasoft.opensearch.security.ssl.rest;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.common.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.ssl.SecurityKeyStore;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.rest.RestRequest.Method.PUT;


/**
 * Rest API action to reload SSL certificates.
 * Can be used to reload SSL certificates that are about to expire without restarting OpenSearch node.
 * This API assumes that new certificates are in the same location specified by the security configurations in opensearch.yml
 * (https://docs-beta.opensearch.org/docs/security-configuration/tls/)
 * To keep sensitive certificate reload secure, this API will only allow hot reload
 * with certificates issued by the same Issuer and Subject DN and SAN with expiry dates after the current one.
 * Currently this action serves PUT request for /_opendistro/_security/ssl/http/reloadcerts or /_opendistro/_security/ssl/transport/reloadcerts endpoint
 */
public class SecuritySSLReloadCertsAction extends BaseRestHandler {
    private static final List<Route> routes = Collections.singletonList(
            new Route(PUT, "_opendistro/_security/api/ssl/{certType}/reloadcerts/")
    );

    private final Settings settings;
    private final SecurityKeyStore sks;
    private final ThreadContext threadContext;
    private final AdminDNs adminDns;

    public SecuritySSLReloadCertsAction(final Settings settings,
                                        final RestController restController,
                                        final SecurityKeyStore sks,
                                        final ThreadPool threadPool,
                                        final AdminDNs adminDns) {
        super();
        this.settings = settings;
        this.sks = sks;
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    /**
     * PUT request to reload SSL Certificates.
     *
     * Sample request:
     * PUT _opendistro/_security/api/ssl/transport/reloadcerts
     * PUT _opendistro/_security/api/ssl/http/reloadcerts
     *
     * NOTE: No request body is required. We will assume new certificates are loaded in the paths specified in your opensearch.yml file
     * (https://docs-beta.opensearch.org/docs/security/configuration/tls/)
     *
     * Sample response:
     * { "message": "updated http certs" }
     *
     * @param request request to be served
     * @param client client
     * @throws IOException
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            final String certType = request.param("certType").toLowerCase().trim();

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                // Check for Super admin user
                final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                if(user ==null||!adminDns.isAdmin(user)) {
                    response = new BytesRestResponse(RestStatus.FORBIDDEN, "");
                } else {
                    try {
                        builder.startObject();
                        if (sks != null) {
                            switch (certType) {
                                case "http":
                                    sks.initHttpSSLConfig();
                                    builder.field("message", "updated http certs");
                                    builder.endObject();
                                    response = new BytesRestResponse(RestStatus.OK, builder);
                                    break;
                                case "transport":
                                    sks.initTransportSSLConfig();
                                    builder.field("message", "updated transport certs");
                                    builder.endObject();
                                    response = new BytesRestResponse(RestStatus.OK, builder);
                                    break;
                                default:
                                    builder.field("message", "invalid uri path, please use /_opendistro/_security/api/ssl/http/reload or " +
                                        "/_opendistro/_security/api/ssl/transport/reload");
                                    builder.endObject();
                                    response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                                    break;
                            }
                        } else {
                            builder.field("message", "keystore is not initialized");
                            builder.endObject();
                            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                        }
                    } catch (final Exception e1) {
                        builder = channel.newBuilder();
                        builder.startObject();
                        builder.field("error", e1.toString());
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                    } finally {
                        if (builder != null) {
                            builder.close();
                        }
                    }
                }
                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "SSL Cert Reload Action";
    }
}
