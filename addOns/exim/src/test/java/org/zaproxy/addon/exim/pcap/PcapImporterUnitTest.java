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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link PcapImporter}. */
class PcapImporterUnitTest extends TestUtils {
    // no tests implemented yet

    @BeforeAll
    static void setup() {}

    @AfterAll
    static void cleanup() {}

    @Test
    void shouldHaveValidAndCompleteHttp1Messages() {
        List<HttpMessage> messages =
                PcapImporter.getHttpMessages(getResourcePath("http1.1SmallAndClean.pcap").toFile());

        assertThat(messages.get(0).isResponseFromTargetHost(), is(equalTo(true)));
        assertThat(
                messages.get(0).getRequestHeader().getURI().toString(),
                is(equalTo("http://www.ethereal.com/download.html")));
        assertThat(messages.get(0).getRequestBody().length(), is(equalTo(0)));
        assertThat(messages.get(0).getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(messages.get(0).getResponseBody().getCharset(), is(equalTo("ISO-8859-1")));

        assertThat(messages.get(1).isResponseFromTargetHost(), is(equalTo(true)));
        assertThat(
                messages.get(1).getRequestHeader().getURI().toString().length(), is(equalTo(282)));
        assertThat(messages.get(1).getRequestBody().length(), is(equalTo(0)));
        assertThat(messages.get(1).getResponseHeader().getStatusCode(), is(equalTo(200)));
        assertThat(messages.get(1).getResponseBody().getCharset(), is(equalTo("ISO-8859-1")));
    }
}
