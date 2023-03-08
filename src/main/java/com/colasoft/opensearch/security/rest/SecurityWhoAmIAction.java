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
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.ssl.util.SSLRequestHelper;
import com.colasoft.opensearch.security.ssl.util.SSLRequestHelper.SSLInfo;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.support.WildcardMatcher;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.rest.RestRequest.Method.GET;
import static com.colasoft.opensearch.rest.RestRequest.Method.POST;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;


public class SecurityWhoAmIAction extends BaseRestHandler {

	private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
			new Route(GET, "/whoami"),
			new Route(POST, "/whoami")),
			"/_plugins/_security");

	private final Logger log = LogManager.getLogger(this.getClass());
	private final AdminDNs adminDns;
	private final Settings settings;
	private final Path configPath;
	private final PrincipalExtractor principalExtractor;
	private final List<String> nodesDn ;

	public SecurityWhoAmIAction(final Settings settings, final RestController controller,
			final ThreadPool threadPool, final AdminDNs adminDns, Path configPath, PrincipalExtractor principalExtractor) {
		super();
		this.adminDns = adminDns;
		this.settings = settings;
		this.configPath = configPath;
		this.principalExtractor = principalExtractor;

		nodesDn = settings.getAsList(ConfigConstants.SECURITY_NODES_DN, Collections.emptyList());
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
				XContentBuilder builder = channel.newBuilder();
				BytesRestResponse response = null;

				try {

					SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor);

					if(sslInfo  == null) {
						response = new BytesRestResponse(RestStatus.FORBIDDEN, "No security data");
					} else {

						final String dn = sslInfo.getPrincipal();
						final boolean isAdmin = adminDns.isAdminDN(dn);
						final boolean isNodeCertificateRequest = dn != null && WildcardMatcher.from(nodesDn, true).matchAny(dn);

						builder.startObject();
						builder.field("dn", dn);
						builder.field("is_admin", isAdmin);
						builder.field("is_node_certificate_request", isNodeCertificateRequest);
						builder.endObject();

						response = new BytesRestResponse(RestStatus.OK, builder);

					}
				} catch (final Exception e1) {
					log.error(e1.toString(), e1);
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

				channel.sendResponse(response);
			}
		};
	}

	@Override
	public String getName() {
		return "Security Plugin Who am i";
	}

}
