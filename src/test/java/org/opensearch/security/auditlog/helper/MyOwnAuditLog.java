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

package com.colasoft.opensearch.security.auditlog.helper;

import java.io.IOException;
import java.nio.file.Path;

import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.security.auditlog.impl.AuditMessage;
import com.colasoft.opensearch.security.auditlog.sink.AuditLogSink;
import com.colasoft.opensearch.threadpool.ThreadPool;

public class MyOwnAuditLog extends AuditLogSink {

	public MyOwnAuditLog(final String name, final Settings settings, final String settingsPrefix, final Path configPath, final ThreadPool threadPool,
	        final IndexNameExpressionResolver resolver, final ClusterService clusterService, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);
    }

    @Override
	public void close() throws IOException {

	}


	public boolean doStore(AuditMessage msg) {
		return true;
	}

}
