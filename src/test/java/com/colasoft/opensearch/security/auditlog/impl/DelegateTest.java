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

package com.colasoft.opensearch.security.auditlog.impl;

import org.junit.Test;

import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.settings.Settings.Builder;
import com.colasoft.opensearch.security.auditlog.helper.MyOwnAuditLog;
import com.colasoft.opensearch.security.auditlog.sink.AuditLogSink;
import com.colasoft.opensearch.security.auditlog.sink.DebugSink;
import com.colasoft.opensearch.security.auditlog.sink.ExternalOpenSearchSink;
import com.colasoft.opensearch.security.auditlog.sink.InternalOpenSearchSink;

public class DelegateTest {
	@Test
	public void auditLogTypeTest() throws Exception{
		testAuditType("DeBUg", DebugSink.class);
		testAuditType("intERnal_OpenSearch", InternalOpenSearchSink.class);
		testAuditType("EXTERnal_OpenSearch", ExternalOpenSearchSink.class);
		testAuditType("com.colasoft.opensearch.security.auditlog.sink.MyOwnAuditLog", MyOwnAuditLog.class);
		testAuditType("com.colasoft.opensearch.security.auditlog.sink.MyOwnAuditLog", null);
		testAuditType("idonotexist", null);
	}

	private void testAuditType(String type, Class<? extends AuditLogSink> expectedClass) throws Exception {
		Builder settingsBuilder  = Settings.builder();
		settingsBuilder.put("plugins.security.audit.type", type);
		settingsBuilder.put("path.home", ".");
		AuditLogImpl auditLog = new AuditLogImpl(settingsBuilder.build(), null, null, null, null, null);
		auditLog.close();
//		if (expectedClass != null) {
//		    Assert.assertNotNull("delegate is null for type: "+type,auditLog.delegate);
//			Assert.assertEquals(expectedClass, auditLog.delegate.getClass());
//		} else {
//			Assert.assertNull(auditLog.delegate);
//		}

	}
}
