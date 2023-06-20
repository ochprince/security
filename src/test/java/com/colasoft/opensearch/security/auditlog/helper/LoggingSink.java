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

package com.colasoft.opensearch.security.auditlog.helper;

import java.util.ArrayList;
import java.util.List;

import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.security.auditlog.impl.AuditMessage;
import com.colasoft.opensearch.security.auditlog.sink.AuditLogSink;

public class LoggingSink extends AuditLogSink {

	public List<AuditMessage> messages = new ArrayList<AuditMessage>(100);
    public StringBuffer sb = new StringBuffer();

    public LoggingSink(String name, Settings settings, String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }


    public boolean doStore(AuditMessage msg) {
        sb.append(msg.toPrettyString()+System.lineSeparator());
        messages.add(msg);
        return true;
    }

    public synchronized void clear() {
        sb.setLength(0);
        messages.clear();
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

}
