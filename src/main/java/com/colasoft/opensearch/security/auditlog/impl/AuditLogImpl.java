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

package com.colasoft.opensearch.security.auditlog.impl;

import java.io.IOException;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;

import org.greenrobot.eventbus.Subscribe;

import com.colasoft.opensearch.SpecialPermission;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.env.Environment;
import com.colasoft.opensearch.index.engine.Engine.Delete;
import com.colasoft.opensearch.index.engine.Engine.DeleteResult;
import com.colasoft.opensearch.index.engine.Engine.Index;
import com.colasoft.opensearch.index.engine.Engine.IndexResult;
import com.colasoft.opensearch.index.get.GetResult;
import com.colasoft.opensearch.index.shard.ShardId;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.security.auditlog.config.AuditConfig;
import com.colasoft.opensearch.security.auditlog.routing.AuditMessageRouter;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.TransportRequest;

public final class AuditLogImpl extends AbstractAuditLog {

	private final AuditMessageRouter messageRouter;
	private final Settings settings;
	private final boolean messageRouterEnabled;
	private volatile boolean enabled;
	private final Thread shutdownHook;

	public AuditLogImpl(final Settings settings,
			final Path configPath,
			final Client clientProvider,
			final ThreadPool threadPool,
			final IndexNameExpressionResolver resolver,
			final ClusterService clusterService) {
		this(settings, configPath, clientProvider, threadPool, resolver, clusterService, null);
	}

    @SuppressWarnings("removal")
	public AuditLogImpl(final Settings settings,
						final Path configPath,
						final Client clientProvider,
						final ThreadPool threadPool,
						final IndexNameExpressionResolver resolver,
						final ClusterService clusterService,
						final Environment environment) {
		super(settings, threadPool, resolver, clusterService, environment);
		this.settings = settings;
		this.messageRouter = new AuditMessageRouter(settings, clientProvider, threadPool, configPath);
		this.messageRouterEnabled = this.messageRouter.isEnabled();

		log.info("Message routing enabled: {}", this.messageRouterEnabled);

		SpecialPermission.check();
		shutdownHook = AccessController.doPrivileged((PrivilegedAction<Thread>) this::addShutdownHook);
		log.debug("Shutdown hook {} registered", shutdownHook);
	}

	@Subscribe
	public void setConfig(final AuditConfig auditConfig) {
		enabled = auditConfig.isEnabled() && messageRouterEnabled;
		onAuditConfigFilterChanged(auditConfig.getFilter());
		onComplianceConfigChanged(auditConfig.getCompliance());
	}

	@Override
	protected void enableRoutes() {
		if (messageRouterEnabled) {
			messageRouter.enableRoutes(settings);
		}
	}

    private Thread addShutdownHook() {
        Thread shutdownHook = new Thread(() -> messageRouter.close());
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        return shutdownHook;
    }

    private Boolean removeShutdownHook() {
        return Runtime.getRuntime().removeShutdownHook(shutdownHook);
    }

    @Override
    @SuppressWarnings("removal")
    public void close() throws IOException {

        log.info("Closing {}", getClass().getSimpleName());

        SpecialPermission.check();
        try {
            final boolean removed = AccessController.doPrivileged((PrivilegedAction<Boolean>) this::removeShutdownHook);
            if (removed) {
                log.debug("Shutdown hook {} unregistered", shutdownHook);
                shutdownHook.run();
            } else {
                log.warn("Shutdown hook {} is not registered", shutdownHook);
            }
        } catch (IllegalStateException e) {
            log.debug("Fail to unregister shutdown hook {}. Shutdown is in progress.", shutdownHook, e);
        }
    }

	@Override
	protected void save(final AuditMessage msg) {
		if (enabled) {
			messageRouter.route(msg);
		}
	}

	@Override
	public void logFailedLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
		if (enabled) {
			super.logFailedLogin(effectiveUser, securityAdmin, initiatingUser, request);
		}
	}

	@Override
	public void logSucceededLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
		if (enabled) {
			super.logSucceededLogin(effectiveUser, securityAdmin, initiatingUser, request);
		}
	}

	@Override
	public void logMissingPrivileges(String privilege, String effectiveUser, RestRequest request) {
		if (enabled) {
			super.logMissingPrivileges(privilege, effectiveUser, request);
		}
	}

	@Override
	public void logGrantedPrivileges(String effectiveUser, RestRequest request) {
		if (enabled) {
			super.logGrantedPrivileges(effectiveUser, request);
		}
	}

	@Override
	public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
		if (enabled) {
			super.logMissingPrivileges(privilege, request, task);
		}
	}

	@Override
	public void logGrantedPrivileges(String privilege, TransportRequest request, Task task) {
		if (enabled) {
			super.logGrantedPrivileges(privilege, request, task);
		}
	}

	@Override
	public void logIndexEvent(String privilege, TransportRequest request, Task task) {
		if (enabled) {
			super.logIndexEvent(privilege, request, task);
		}
	}

	@Override
	public void logBadHeaders(TransportRequest request, String action, Task task) {
		if (enabled) {
			super.logBadHeaders(request, action, task);
		}
	}

	@Override
	public void logBadHeaders(RestRequest request) {
		if (enabled) {
			super.logBadHeaders(request);
		}
	}

	@Override
	public void logSecurityIndexAttempt (TransportRequest request, String action, Task task) {
		if (enabled) {
			super.logSecurityIndexAttempt(request, action, task);
		}
	}

	@Override
	public void logSSLException(TransportRequest request, Throwable t, String action, Task task) {
		if (enabled) {
			super.logSSLException(request, t, action, task);
		}
	}

	@Override
	public void logSSLException(RestRequest request, Throwable t) {
		if (enabled) {
			super.logSSLException(request, t);
		}
	}

	@Override
	public void logDocumentRead(String index, String id, ShardId shardId, Map<String, String> fieldNameValues) {
		if (enabled) {
			super.logDocumentRead(index, id, shardId, fieldNameValues);
		}
	}

	@Override
	public void logDocumentWritten(ShardId shardId, GetResult originalResult, Index currentIndex, IndexResult result) {
		if (enabled) {
			super.logDocumentWritten(shardId, originalResult, currentIndex, result);
		}
	}

	@Override
	public void logDocumentDeleted(ShardId shardId, Delete delete, DeleteResult result) {
		if (enabled) {
			super.logDocumentDeleted(shardId, delete, result);
		}
	}

	@Override
	protected void logExternalConfig() {
		if (enabled) {
			super.logExternalConfig();
		}
	}

}
