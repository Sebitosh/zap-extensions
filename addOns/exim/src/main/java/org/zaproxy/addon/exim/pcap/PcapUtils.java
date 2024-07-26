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

import io.pkts.Pcap;
import io.pkts.packet.TCPPacket;
import io.pkts.streams.StreamId;
import io.pkts.streams.TcpStream;
import io.pkts.streams.impl.TcpStreamHandler;
import io.pkts.streams.impl.TransportStreamId;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public final class PcapUtils {

    private static final Logger LOGGER = LogManager.getLogger(PcapUtils.class);

    public static Map<StreamId, TcpStream> extractTcpStreams(File pcapFile) {
        TcpStreamHandler streamHandler = new TcpStreamHandler();
        try {
            final Pcap pcap = Pcap.openStream(pcapFile);
            pcap.loop(streamHandler);
            pcap.close();
        } catch (IOException e) {
            LOGGER.error("Failed to open pcap file: " + e.getMessage());
        }

        return streamHandler.getStreams();
    }

    public static Collection<TcpStream> extractHttpStreams(File pcapFile) {
        Map<StreamId, TcpStream> tcpStreams = extractTcpStreams(pcapFile);
        Collection<TcpStream> httpStreams = new LinkedList<>();
        Collection<TcpStream> streams = tcpStreams.values();

        for (TcpStream stream : streams) {
            if (isHttpStream(stream)) {
                httpStreams.add(stream);
            }
        }
        return httpStreams;
    }

    // TODO: Implement robust http stream detection
    // For now, we only detect if the first tcp segment contains a valid HttpRequestHeader
    private static boolean isHttpStream(TcpStream stream) {
        List<TCPPacket> packets = stream.getPackets();
        for (TCPPacket packet : packets) {
            if (packet.getPayload() != null && !packet.getPayload().isEmpty()) {
                try {
                    HttpRequestHeader reqHeader =
                            new HttpRequestHeader(packet.getPayload().toString());
                    return true;
                } catch (HttpMalformedHeaderException e) {
                    return false;
                }
            }
        }
        return false;
    }

    // TODO: Implement robust http flow reconstruction
    // For now we ignore retransmission/missing/overlapping/out-of-order data in tcp segments.
    public static String getHttpRequestFlow(TcpStream stream) {
        List<TCPPacket> tcpPackets = stream.getPackets();
        StringBuilder requestFlow = new StringBuilder();
        TransportStreamId requestDirection =
                new TransportStreamId(tcpPackets.get(0)); // client is opening the tcp connection
        for (TCPPacket tcpPacket : tcpPackets) {
            if (tcpPacket.getPayload() != null
                    && requestDirection.equals(new TransportStreamId(tcpPacket))) {
                requestFlow.append(
                        tcpPacket
                                .getPayload()
                                .toString()); // naively reassemble the client requests
            }
        }
        return requestFlow.toString();
    }

    public static String getHttpResponseFlow(TcpStream stream) {
        List<TCPPacket> tcpPackets = stream.getPackets();
        StringBuilder responseFlow = new StringBuilder();
        TransportStreamId responseDirection =
                new TransportStreamId(tcpPackets.get(0))
                        .oppositeFlowDirection(); // server is receiving connection
        for (TCPPacket tcpPacket : tcpPackets) {
            if (tcpPacket.getPayload() != null
                    && responseDirection.equals(new TransportStreamId(tcpPacket))) {
                responseFlow.append(
                        tcpPacket
                                .getPayload()
                                .toString()); // naively reassemble the server responses
            }
        }
        return responseFlow.toString();
    }

    public static List<HttpMessage> constructHttpMessages(String requestFlow, String responseFlow) {
        List<HttpMessage> requestsMessages = constructHttpRequests(requestFlow);
        return constructHttpResponses(responseFlow, requestsMessages);
    }

    private static List<HttpMessage> constructHttpRequests(String requestFlow) {
        List<HttpMessage> requests = new ArrayList<>();
        ArrayList<String> flow = new ArrayList<>(List.of(requestFlow.split("\r\n\r\n")));

        ListIterator<String> flowIt = flow.listIterator();

        while (flowIt.hasNext()) {
            HttpRequestHeader reqHeader = new HttpRequestHeader();
            HttpRequestBody reqBody = new HttpRequestBody();
            try {
                reqHeader = new HttpRequestHeader(flowIt.next());
                if (flowIt.hasNext()) {
                    try {
                        // if the lookahead is a header, then the request has an empty body
                        HttpRequestHeader lookahead = new HttpRequestHeader(flowIt.next());
                        flowIt.previous();
                    } catch (HttpMalformedHeaderException e) {
                        flowIt.previous();
                        reqBody = new HttpRequestBody(flowIt.next());
                    }
                }
            } catch (HttpMalformedHeaderException e) {
                // we assume the header will always come first
                LOGGER.error("Failed to parse request header: " + e.getMessage());
            } finally {
                requests.add(new HttpMessage(reqHeader, reqBody));
            }
        }

        return requests;
    }

    private static List<HttpMessage> constructHttpResponses(
            String responseFlow, List<HttpMessage> requests) {
        List<HttpMessage> messages = new ArrayList<>();
        ArrayList<String> flow = new ArrayList<>(List.of(responseFlow.split("\r\n\r\n")));

        int reqIndex = 0;
        ListIterator<String> flowIt = flow.listIterator();
        while (flowIt.hasNext()) {
            HttpResponseHeader resHeader = new HttpResponseHeader();
            HttpResponseBody resBody = new HttpResponseBody();
            try {
                resHeader = new HttpResponseHeader(flowIt.next());
                if (flowIt.hasNext()) {
                    try {
                        HttpResponseHeader lookahead = new HttpResponseHeader(flowIt.next());
                        flowIt.previous();
                    } catch (HttpMalformedHeaderException e) {
                        flowIt.previous();
                        resBody = new HttpResponseBody(flowIt.next().getBytes());
                    }
                }
            } catch (HttpMalformedHeaderException e) {
                // we assume the header will always come first
                LOGGER.error("Failed to parse response header: " + e.getMessage());
            } finally {
                // We assume 1) that there are as many responses as requests
                // and 2) that they are in order (http 1.x)
                HttpMessage message = requests.get(reqIndex);
                message.setResponseHeader(resHeader);
                message.setResponseBody(resBody); // may be empty
                message.setResponseFromTargetHost(true);
                messages.add(message);
                reqIndex++;
            }
        }
        return messages;
    }
}
