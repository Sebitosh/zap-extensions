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
package org.zaproxy.addon.exim.pcap;

import io.pkts.streams.TcpStream;
import java.io.File;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;

public class PcapImporter {

    private ProgressPaneListener progressListener;
    private boolean success;

    public PcapImporter(File file) {
        this(file, null);
    }

    public PcapImporter(File file, ProgressPaneListener listener) {
        this.progressListener = listener;
        this.success = importPcapFile(file);
        completed();
    }

    private boolean importPcapFile(File file) {
        // no import logic implemented yet
        return false;
    }

    protected static List<HttpMessage> getHttpMessages(File pcapFile) {
        List<HttpMessage> httpMessages = new LinkedList<>();
        Collection<TcpStream> httpStreams = PcapUtils.extractHttpStreams(pcapFile);

        for (TcpStream httpStream : httpStreams) {
            String requestFlow = PcapUtils.getHttpRequestFlow(httpStream);
            byte[] responseFlow = PcapUtils.getHttpResponseFlow(httpStream);
            httpMessages.addAll(PcapUtils.constructHttpMessages(requestFlow, responseFlow));
        }

        return httpMessages;
    }

    private void completed() {
        if (progressListener != null) {
            progressListener.completed();
        }
    }
}
