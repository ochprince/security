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

package com.colasoft.opensearch.security.auditlog;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.colasoft.opensearch.security.auditlog.compliance.ComplianceAuditlogTest;
import com.colasoft.opensearch.security.auditlog.compliance.RestApiComplianceAuditlogTest;
import com.colasoft.opensearch.security.auditlog.impl.AuditlogTest;
import com.colasoft.opensearch.security.auditlog.impl.DelegateTest;
import com.colasoft.opensearch.security.auditlog.impl.DisabledCategoriesTest;
import com.colasoft.opensearch.security.auditlog.impl.IgnoreAuditUsersTest;
import com.colasoft.opensearch.security.auditlog.impl.TracingTests;
import com.colasoft.opensearch.security.auditlog.integration.BasicAuditlogTest;
import com.colasoft.opensearch.security.auditlog.integration.SSLAuditlogTest;
import com.colasoft.opensearch.security.auditlog.routing.FallbackTest;
import com.colasoft.opensearch.security.auditlog.routing.RouterTest;
import com.colasoft.opensearch.security.auditlog.routing.RoutingConfigurationTest;
import com.colasoft.opensearch.security.auditlog.sink.KafkaSinkTest;
import com.colasoft.opensearch.security.auditlog.sink.SinkProviderTLSTest;
import com.colasoft.opensearch.security.auditlog.sink.SinkProviderTest;
import com.colasoft.opensearch.security.auditlog.sink.WebhookAuditLogTest;

@RunWith(Suite.class)

@Suite.SuiteClasses({
	ComplianceAuditlogTest.class,
	RestApiComplianceAuditlogTest.class,
	AuditlogTest.class,
	DelegateTest.class,
	DisabledCategoriesTest.class,
	IgnoreAuditUsersTest.class,
	TracingTests.class,
	BasicAuditlogTest.class,
	SSLAuditlogTest.class,
	FallbackTest.class,
	RouterTest.class,
	RoutingConfigurationTest.class,
	SinkProviderTest.class,
	SinkProviderTLSTest.class,
	WebhookAuditLogTest.class,
	KafkaSinkTest.class
})
public class AuditLogTestSuite {

}
