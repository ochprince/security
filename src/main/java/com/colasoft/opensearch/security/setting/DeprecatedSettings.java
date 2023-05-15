/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.colasoft.opensearch.security.setting;

import com.colasoft.opensearch.common.logging.DeprecationLogger;
import com.colasoft.opensearch.common.settings.Settings;

/**
 * Functionality around settings that have been deprecated
 */
public class DeprecatedSettings {

    static DeprecationLogger DEPRECATION_LOGGER = DeprecationLogger.getLogger(DeprecatedSettings.class);

    /**
     * Checks for an deprecated key found in a setting, logs that it should be replaced with the another key
     */
    public static void checkForDeprecatedSetting(final Settings settings, final String legacySettingKey, final String validSettingKey) {
        if (settings.hasValue(legacySettingKey)) {
            DEPRECATION_LOGGER.deprecate(legacySettingKey, "Found deprecated setting '{}', please replace with '{}'", legacySettingKey, validSettingKey);
        }
    }
}
