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

package com.colasoft.opensearch.security.auditlog.sink;

import java.io.IOException;
import java.nio.file.Path;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.colasoft.opensearch.action.index.IndexRequestBuilder;
import com.colasoft.opensearch.action.support.WriteRequest.RefreshPolicy;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.unit.TimeValue;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import com.colasoft.opensearch.security.auditlog.impl.AuditMessage;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.support.HeaderHelper;
import com.colasoft.opensearch.threadpool.ThreadPool;

public final class InternalOpenSearchSink extends AuditLogSink {

	private final Client clientProvider;
	final String index;
	final String type;
	private DateTimeFormatter indexPattern;
	private final ThreadPool threadPool;

	public InternalOpenSearchSink(final String name, final Settings settings, final String settingsPrefix, final Path configPath, final Client clientProvider, ThreadPool threadPool, AuditLogSink fallbackSink) {
		super(name, settings, settingsPrefix, fallbackSink);
		this.clientProvider = clientProvider;
		Settings sinkSettings = getSinkSettings(settingsPrefix);

		this.index = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX, "'security-auditlog-'YYYY.MM.dd");
		this.type = sinkSettings.get(ConfigConstants.SECURITY_AUDIT_OPENSEARCH_TYPE, null);

		this.threadPool = threadPool;
		try {
			this.indexPattern = DateTimeFormat.forPattern(index);
		} catch (IllegalArgumentException e) {
			log.debug("Unable to parse index pattern due to {}. " + "If you have no date pattern configured you can safely ignore this message", e.getMessage());
		}
	}

	@Override
	public void close() throws IOException {

	}

	public boolean doStore(final AuditMessage msg) {

		if (Boolean.parseBoolean((String) HeaderHelper.getSafeFromHeader(threadPool.getThreadContext(), ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER))) {
			if (log.isTraceEnabled()) {
				log.trace("audit log of audit log will not be executed");
			}
			return true;
		}

		try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {
			try {
				final IndexRequestBuilder irb = clientProvider.prepareIndex(getExpandedIndexName(indexPattern, index)).setRefreshPolicy(RefreshPolicy.IMMEDIATE).setSource(msg.getAsMap());
				threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
				irb.setTimeout(TimeValue.timeValueMinutes(1));
				irb.execute().actionGet();
				return true;
			} catch (final Exception e) {
				log.error("Unable to index audit log {} due to", msg, e);
				return false;
			}
		}
	}
}
