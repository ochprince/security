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

package com.colasoft.opensearch.security.filter;

import java.util.Arrays;
import java.util.Collection;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;

import com.colasoft.opensearch.OpenSearchSecurityException;
import com.colasoft.opensearch.action.ActionListener;
import com.colasoft.opensearch.action.ActionResponse;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.CompatConfig;
import com.colasoft.opensearch.security.configuration.DlsFlsRequestValve;
import com.colasoft.opensearch.security.http.XFFResolver;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.resolver.IndexResolverReplacer;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.support.WildcardMatcher;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class SecurityFilterTest {

    private final Settings settings;
    private final WildcardMatcher expected;

    public SecurityFilterTest(Settings settings, WildcardMatcher expected) {
        this.settings = settings;
        this.expected = expected;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {Settings.EMPTY, WildcardMatcher.NONE},
                {Settings.builder()
                        .putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2")
                        .build(),
                        WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2"))},
                {Settings.builder()
                        .putList(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, "immutable1", "immutable2", "immutable2")
                        .build(),
                        WildcardMatcher.from(ImmutableSet.of("immutable1", "immutable2"))},
        });
    }

    @Test
    public void testImmutableIndicesWildcardMatcher() {
        final SecurityFilter filter = new SecurityFilter(
                settings,
                mock(PrivilegesEvaluator.class),
                mock(AdminDNs.class),
                mock(DlsFlsRequestValve.class),
                mock(AuditLog.class),
                mock(ThreadPool.class),
                mock(ClusterService.class),
                mock(CompatConfig.class),
                mock(IndexResolverReplacer.class),
                mock(XFFResolver.class)
        );
        assertThat(expected, equalTo(filter.getImmutableIndicesMatcher()));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUnexepectedCausesAreNotSendToCallers() {
        // Setup
        final AuditLog auditLog = mock(AuditLog.class);
        when(auditLog.getComplianceConfig()).thenThrow(new RuntimeException("ABC!"));
        final ActionListener<ActionResponse> listener = mock(ActionListener.class);

        final SecurityFilter filter = new SecurityFilter(
            settings,
            mock(PrivilegesEvaluator.class),
            mock(AdminDNs.class),
            mock(DlsFlsRequestValve.class),
            auditLog,
            new ThreadPool(Settings.builder().put("node.name",  "mock").build()),
            mock(ClusterService.class),
            mock(CompatConfig.class),
            mock(IndexResolverReplacer.class),
            mock(XFFResolver.class)
        );

        // Act
        filter.apply(null, null, null, listener, null);

        // Verify
        verify(auditLog).getComplianceConfig(); // Make sure the exception was thrown

        final ArgumentCaptor<OpenSearchSecurityException> cap = ArgumentCaptor.forClass(OpenSearchSecurityException.class);
        verify(listener).onFailure(cap.capture());

        assertThat("The cause should never be included as it will leak to callers", cap.getValue().getCause(), nullValue()); 
        assertThat("Make sure the cause exception wasn't toStringed in the method", cap.getValue().getMessage(), not(containsString("ABC!")));

        verifyNoMoreInteractions(auditLog, listener);
    }
}
