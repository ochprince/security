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

package com.colasoft.opensearch.security.transport;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import com.google.common.base.Strings;

import com.colasoft.opensearch.OpenSearchException;
import com.colasoft.opensearch.OpenSearchSecurityException;
import com.colasoft.opensearch.action.bulk.BulkShardRequest;
import com.colasoft.opensearch.action.support.replication.TransportReplicationAction.ConcreteShardRequest;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.transport.TransportAddress;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.search.internal.ShardSearchRequest;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.auditlog.AuditLog.Origin;
import com.colasoft.opensearch.security.ssl.SslExceptionHandler;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.ssl.transport.SSLConfig;
import com.colasoft.opensearch.security.ssl.transport.SecuritySSLRequestHandler;
import com.colasoft.opensearch.security.ssl.util.ExceptionUtils;
import com.colasoft.opensearch.security.support.Base64Helper;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.support.HeaderHelper;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.TransportChannel;
import com.colasoft.opensearch.transport.TransportRequest;
import com.colasoft.opensearch.transport.TransportRequestHandler;

import static com.colasoft.opensearch.security.OpenSearchSecurityPlugin.isActionTraceEnabled;

public class SecurityRequestHandler<T extends TransportRequest> extends SecuritySSLRequestHandler<T> {

    private final AuditLog auditLog;
    private final InterClusterRequestEvaluator requestEvalProvider;
    private final ClusterService cs;

        SecurityRequestHandler(String action,
            final TransportRequestHandler<T> actualHandler,
            final ThreadPool threadPool,
            final AuditLog auditLog,
            final PrincipalExtractor principalExtractor,
            final InterClusterRequestEvaluator requestEvalProvider,
            final ClusterService cs,
            final SSLConfig SSLConfig,
            final SslExceptionHandler sslExceptionHandler) {
        super(action, actualHandler, threadPool, principalExtractor, SSLConfig, sslExceptionHandler);
        this.auditLog = auditLog;
        this.requestEvalProvider = requestEvalProvider;
        this.cs = cs;
    }

    @Override
    protected void messageReceivedDecorate(final T request, final TransportRequestHandler<T> handler,
            final TransportChannel transportChannel, Task task) throws Exception {

        String resolvedActionClass = request.getClass().getSimpleName();

        if(request instanceof BulkShardRequest) {
            if(((BulkShardRequest) request).items().length == 1) {
                resolvedActionClass = ((BulkShardRequest) request).items()[0].request().getClass().getSimpleName();
            }
        }

        if(request instanceof ConcreteShardRequest) {
            resolvedActionClass = ((ConcreteShardRequest<?>) request).getRequest().getClass().getSimpleName();
        }

        String initialActionClassValue = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER);

        final ThreadContext.StoredContext sgContext = getThreadContext().newStoredContext(false);

        final String originHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER);

        if(!Strings.isNullOrEmpty(originHeader)) {
            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originHeader);
        }

        try {

            if(transportChannel.getChannelType() == null) {
                throw new RuntimeException("Can not determine channel type (null)");
            }

            String channelType = transportChannel.getChannelType();

            if (!channelType.equals("direct") && !channelType.equals("transport")) {
                TransportChannel innerChannel = getInnerChannel(transportChannel);
                channelType = innerChannel.getChannelType();
            }

            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE, channelType);
            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ACTION_NAME, task.getAction());

            if(request instanceof ShardSearchRequest) {
                ShardSearchRequest sr = ((ShardSearchRequest) request);
                if(sr.source() != null && sr.source().suggest() != null) {
                    getThreadContext().putTransient("_opendistro_security_issuggest", Boolean.TRUE);
                }
            }

            //bypass non-netty requests
            if(channelType.equals("direct")) {
                final String userHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                final String injectedRolesHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER);
                final String injectedUserHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_HEADER);

                if(Strings.isNullOrEmpty(userHeader)) {
                    // Keeping role injection with higher priority as plugins under OpenSearch will be using this
                    // on transport layer
                    if(!Strings.isNullOrEmpty(injectedRolesHeader)) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRolesHeader);
                    }
                    else if(!Strings.isNullOrEmpty(injectedUserHeader)) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUserHeader);
                    }
                } else {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, Objects.requireNonNull((User) Base64Helper.deserializeObject(userHeader)));
                }

                final String originalRemoteAddress = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER);

                if(!Strings.isNullOrEmpty(originalRemoteAddress)) {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(originalRemoteAddress)));
                }

                final String rolesValidation = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION_HEADER);
                if(!Strings.isNullOrEmpty(rolesValidation)) {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, rolesValidation);
                }

                if (isActionTraceEnabled()) {
                    getThreadContext().putHeader("_opendistro_security_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" DIR -> "+transportChannel.getChannelType()+" "+getThreadContext().getHeaders());
                }

                putInitialActionClassHeader(initialActionClassValue, resolvedActionClass);

                super.messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }

            boolean skipSecurityIfDualMode = getThreadContext().getTransient(ConfigConstants.SECURITY_SSL_DUAL_MODE_SKIP_SECURITY) == Boolean.TRUE;

                if(skipSecurityIfDualMode) {
                    if(getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS) == null) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, request.remoteAddress());
                    }

                    if(getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN) == null) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.TRANSPORT.toString());
                    }

                    if (getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST) == null) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, Boolean.TRUE);
                    }

                    super.messageReceivedDecorate(request, handler, transportChannel, task);
                    return;
            }

            //if the incoming request is an internal:* or a shard request allow only if request was sent by a server node
            //if transport channel is not a netty channel but a direct or local channel (e.g. send via network) then allow it (regardless of beeing a internal: or shard request)
            //also allow when issued from a remote cluster for cross cluster search
            if ( !HeaderHelper.isInterClusterRequest(getThreadContext())
                    && !HeaderHelper.isTrustedClusterRequest(getThreadContext())
                    && !task.getAction().equals("internal:transport/handshake")
                    && (task.getAction().startsWith("internal:") || task.getAction().contains("["))) {

                auditLog.logMissingPrivileges(task.getAction(), request, task);
                log.error("Internal or shard requests ("+task.getAction()+") not allowed from a non-server node for transport type "+transportChannel.getChannelType());
                transportChannel.sendResponse(new OpenSearchSecurityException(
                            "Internal or shard requests not allowed from a non-server node for transport type "+transportChannel.getChannelType()));
                return;
                    }


            String principal = null;

            if ((principal = getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL)) == null) {
                Exception ex = new OpenSearchSecurityException(
                        "No SSL client certificates found for transport type "+transportChannel.getChannelType()+". OpenSearch Security needs the OpenSearch Security SSL plugin to be installed");
                auditLog.logSSLException(request, ex, task.getAction(), task);
                log.error("No SSL client certificates found for transport type "+transportChannel.getChannelType()+". OpenSearch Security needs the OpenSearch Security SSL plugin to be installed");
                transportChannel.sendResponse(ex);
                return;
            } else {

                if(getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN) == null) {
                    getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.TRANSPORT.toString());
                }

                //network intercluster request or cross search cluster request
                if(HeaderHelper.isInterClusterRequest(getThreadContext())
                        || HeaderHelper.isTrustedClusterRequest(getThreadContext())) {

                    final String userHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                    final String injectedRolesHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER);
                    final String injectedUserHeader = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_HEADER);

                    if(Strings.isNullOrEmpty(userHeader)) {
                        // Keeping role injection with higher priority as plugins under OpenSearch will be using this
                        // on transport layer
                        if(!Strings.isNullOrEmpty(injectedRolesHeader)) {
                            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRolesHeader);
                        }
                        else if(!Strings.isNullOrEmpty(injectedUserHeader)) {
                            getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUserHeader);
                        }
                    } else {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, Objects.requireNonNull((User) Base64Helper.deserializeObject(userHeader)));
                    }

                    String originalRemoteAddress = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER);

                    if(!Strings.isNullOrEmpty(originalRemoteAddress)) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(originalRemoteAddress)));
                    } else {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, request.remoteAddress());
                    }

                    final String rolesValidation = getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION_HEADER);
                    if(!Strings.isNullOrEmpty(rolesValidation)) {
                        getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, rolesValidation);
                    }

                } else {

                    //this is a netty request from a non-server node (maybe also be internal: or a shard request)
                    //and therefore issued by a transport client

                    //since OS 2.0 we do not support this any longer because transport client no longer available

                    final OpenSearchException exception = ExceptionUtils.createTransportClientNoLongerSupportedException();
                    log.error(exception.toString());
                    transportChannel.sendResponse(exception);
                    return;
                }

                if (isActionTraceEnabled()) {
                    getThreadContext().putHeader("_opendistro_security_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" NETTI -> "+transportChannel.getChannelType()+" "+getThreadContext().getHeaders().entrySet().stream().filter(p->!p.getKey().startsWith("_opendistro_security_trace")).collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue())));
                }


                putInitialActionClassHeader(initialActionClassValue, resolvedActionClass);

                super.messageReceivedDecorate(request, handler, transportChannel, task);
            }
        } finally {

            if (isActionTraceEnabled()) {
                getThreadContext().putHeader("_opendistro_security_trace"+System.currentTimeMillis()+"#"+UUID.randomUUID().toString(), Thread.currentThread().getName()+" FIN -> "+transportChannel.getChannelType()+" "+getThreadContext().getHeaders());
            }

            if(sgContext != null) {
                sgContext.close();
            }
        }
    }
    
    private void putInitialActionClassHeader(String initialActionClassValue, String resolvedActionClass) {
        if(initialActionClassValue == null) {
            if(getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER) == null) {
                getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER, resolvedActionClass);
            }
        } else {
            if(getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER) == null) {
                getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER, initialActionClassValue);
            }
        }

    }

    @Override
    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] localCerts, final X509Certificate[] peerCerts, final String principal)
            throws Exception {

        boolean isInterClusterRequest = requestEvalProvider.isInterClusterRequest(request, localCerts, peerCerts, principal);
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isInterClusterRequest) {
            if(cs.getClusterName().value().equals(getThreadContext().getHeader("_opendistro_security_remotecn"))) {

                if (isTraceEnabled && !action.startsWith("internal:")) {
                    log.trace("Is inter cluster request ({}/{}/{})", action, request.getClass(), request.remoteAddress());
                }

                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_INTERCLUSTER_REQUEST, Boolean.TRUE);
            } else {
                getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST, Boolean.TRUE);
            }

        } else {
            if (isTraceEnabled) {
                log.trace("Is not an inter cluster request");
            }
        }

        super.addAdditionalContextValues(action, request, localCerts, peerCerts, principal);
    }
}
