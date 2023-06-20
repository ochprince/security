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

package com.colasoft.opensearch.security.support;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.colasoft.opensearch.SpecialPermission;
import com.colasoft.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import com.colasoft.opensearch.action.support.PlainActionFuture;
import com.colasoft.opensearch.repositories.RepositoriesService;
import com.colasoft.opensearch.repositories.Repository;
import com.colasoft.opensearch.security.OpenSearchSecurityPlugin;
import com.colasoft.opensearch.snapshots.SnapshotId;
import com.colasoft.opensearch.snapshots.SnapshotInfo;
import com.colasoft.opensearch.snapshots.SnapshotUtils;
import com.colasoft.opensearch.threadpool.ThreadPool;

public class SnapshotRestoreHelper {

    protected static final Logger log = LogManager.getLogger(SnapshotRestoreHelper.class);
    
    public static List<String> resolveOriginalIndices(RestoreSnapshotRequest restoreRequest) {
        final SnapshotInfo snapshotInfo = getSnapshotInfo(restoreRequest);

        if (snapshotInfo == null) {
            log.warn("snapshot repository '{}', snapshot '{}' not found", restoreRequest.repository(), restoreRequest.snapshot());
            return null;
        } else {
            return SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());
        }    
        
        
    }
    
    public static SnapshotInfo getSnapshotInfo(RestoreSnapshotRequest restoreRequest) {
        final RepositoriesService repositoriesService = Objects.requireNonNull(OpenSearchSecurityPlugin.GuiceHolder.getRepositoriesService(), "RepositoriesService not initialized");
        final Repository repository = repositoriesService.repository(restoreRequest.repository());
        final String threadName = Thread.currentThread().getName();
        SnapshotInfo snapshotInfo = null;
        
        try {
            setCurrentThreadName("[" + ThreadPool.Names.GENERIC + "]");
            for (SnapshotId snapshotId : PlainActionFuture.get(repository::getRepositoryData).getSnapshotIds()) {
                if (snapshotId.getName().equals(restoreRequest.snapshot())) {

                    if(log.isDebugEnabled()) {
                        log.debug("snapshot found: {} (UUID: {})", snapshotId.getName(), snapshotId.getUUID());
                    }

                    snapshotInfo = repository.getSnapshotInfo(snapshotId);
                    break;
                }
            }
        } finally {
            setCurrentThreadName(threadName);
        }
        return snapshotInfo;
    }
    
    @SuppressWarnings("removal")
    private static void setCurrentThreadName(final String name) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                Thread.currentThread().setName(name);
                return null;
            }
        });
    }
    
}
