/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.pscan;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.pscan.internal.AddOnScanRulesLoader;
import org.zaproxy.addon.pscan.internal.DefaultStatsListener;
import org.zaproxy.addon.pscan.internal.StatsPassiveScanner;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.StatsListener;
import org.zaproxy.zap.view.ScanStatus;

public class ExtensionPassiveScan2 extends ExtensionAdaptor {

    public static final String NAME = "ExtensionPassiveScan2";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class);

    private final boolean loadScanRules;
    private AddOnScanRulesLoader scanRulesLoader;

    private boolean addScanStatus;
    private ScanStatus scanStatus;
    private StatsListener statsListener;

    public ExtensionPassiveScan2() {
        super(NAME);

        loadScanRules =
                !hasField(
                        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class,
                        "addOnScanRules");
    }

    private static boolean hasField(Class<?> clazz, String name) {
        try {
            clazz.getDeclaredField(name);
            return true;
        } catch (NoSuchFieldException e) {
            // Nothing to do.
        }
        return false;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("pscan.ext.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("pscan.ext.desc");
    }

    @Override
    public void init() {
        if (loadScanRules) {
            scanRulesLoader = new AddOnScanRulesLoader(getExtPscan());
        }

        addScanStatus =
                hasView()
                        && !hasField(
                                org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class,
                                "scanStatus");
    }

    @Override
    public void postInit() {
        if (loadScanRules) {
            scanRulesLoader.load();
        }
        StatsPassiveScanner.load(getExtPscan());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (org.zaproxy.zap.extension.pscan.PassiveScanAPI.class.getAnnotation(Deprecated.class)
                != null) {
            extensionHook.addApiImplementor(new PassiveScanApi(getExtPscan()));
        }

        if (loadScanRules) {
            extensionHook.addAddOnInstallationStatusListener(scanRulesLoader);
        }

        if (addScanStatus) {
            scanStatus =
                    new ScanStatus(
                            DisplayUtils.getScaledIcon(getClass().getResource("icons/pscan.png")),
                            Constant.messages.getString("pscan.footer.label"));
            statsListener =
                    new DefaultStatsListener() {

                        @Override
                        public void highwaterMarkSet(String key, long value) {
                            if ("stats.pscan.recordsToScan".equals(key)) {
                                scanStatus.setScanCount((int) value);
                            }
                        }
                    };
            Stats.addListener(statsListener);

            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }
    }

    private static org.zaproxy.zap.extension.pscan.ExtensionPassiveScan getExtPscan() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (loadScanRules) {
            scanRulesLoader.unload();
        }
        StatsPassiveScanner.unload(getExtPscan());

        if (addScanStatus) {
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightLabel(scanStatus.getCountLabel());

            Stats.removeListener(statsListener);
        }
    }
}
