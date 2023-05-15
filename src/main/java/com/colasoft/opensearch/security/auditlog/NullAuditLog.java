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

package com.colasoft.opensearch.security.auditlog;

import java.io.IOException;
import java.util.Map;

import com.colasoft.opensearch.index.engine.Engine.Delete;
import com.colasoft.opensearch.index.engine.Engine.DeleteResult;
import com.colasoft.opensearch.index.engine.Engine.Index;
import com.colasoft.opensearch.index.engine.Engine.IndexResult;
import com.colasoft.opensearch.index.get.GetResult;
import com.colasoft.opensearch.index.shard.ShardId;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.security.auditlog.config.AuditConfig;
import com.colasoft.opensearch.security.compliance.ComplianceConfig;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.transport.TransportRequest;

public class NullAuditLog implements AuditLog {

    @Override
    public void close() throws IOException {
        //noop, intentionally left empty
    }

    @Override
    public void logFailedLogin(String effectiveUser, boolean securityadmin, String initiatingUser, RestRequest request) {
        //noop, intentionally left empty
    }

    @Override
    public void logSucceededLogin(String effectiveUser, boolean securityadmin, String initiatingUser, RestRequest request) {
        //noop, intentionally left empty
    }

    @Override
    public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
        //noop, intentionally left empty
    }

    @Override
    public void logGrantedPrivileges(String privilege, TransportRequest request, Task task) {
        //noop, intentionally left empty
    }

    @Override
    public void logIndexEvent(String privilege, TransportRequest request, Task task) {
        //noop, intentionally left empty
    }

    @Override
    public void logBadHeaders(TransportRequest request, String action, Task task) {
        //noop, intentionally left empty
    }

    @Override
    public void logBadHeaders(RestRequest request) {
        //noop, intentionally left empty
    }

    @Override
    public void logSecurityIndexAttempt(TransportRequest request, String action, Task task) {
        //noop, intentionally left empty
    }

    @Override
    public void logSSLException(TransportRequest request, Throwable t, String action, Task task) {
        //noop, intentionally left empty
    }

    @Override
    public void logSSLException(RestRequest request, Throwable t) {
        //noop, intentionally left empty
    }

    @Override
    public void logMissingPrivileges(String privilege, String effectiveUser, RestRequest request) {
        //noop, intentionally left empty
    }

    @Override
    public void logGrantedPrivileges(String effectiveUser, RestRequest request) {
        //noop, intentionally left empty
    }

    @Override
    public void logDocumentRead(String index, String id, ShardId shardId, Map<String, String> fieldNameValues) {
        //noop, intentionally left empty
    }

    @Override
    public void logDocumentWritten(ShardId shardId, GetResult originalIndex, Index currentIndex, IndexResult result) {
        //noop, intentionally left empty
    }

    @Override
    public void logDocumentDeleted(ShardId shardId, Delete delete, DeleteResult result) {
        //noop, intentionally left empty
    }

    @Override
    public ComplianceConfig getComplianceConfig() {
        return null;
    }

    @Override
    public void setConfig(AuditConfig auditConfig) {

    }

}
