/*
 * Copyright 2016 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.codec.dns;

import io.netty.channel.socket.InternetProtocolFamily;
import io.netty.util.NetUtil;
import io.netty.util.internal.UnstableApi;

import java.net.InetAddress;

/**
 * Default {@link DnsOptEcsRecord} implementation.
 */
@UnstableApi
public final class DefaultDnsOptEcsRecord extends AbstractDnsOptPseudoRrRecord implements DnsOptEcsRecord {
    private final int srcPrefixLength;
    private final InetAddress address;

    /**
     * Creates a new instance.
     *
     * @param maxPayladSize the suggested max payload size in bytes
     * @param extendedRcode the extended rcode
     * @param version the version
     * @param srcPrefixLength the prefix length
     * @param address the {@link InetAddress} to use
     */
    public DefaultDnsOptEcsRecord(int maxPayladSize, int extendedRcode, int version,
                                  int srcPrefixLength, InetAddress address) {
        super(maxPayladSize, extendedRcode, version);
        this.srcPrefixLength = srcPrefixLength;
        this.address = address;
    }

    /**
     * Creates a new instance.
     *
     * @param maxPayladSize the suggested max payload size in bytes
     * @param srcPrefixLength the prefix length
     * @param address the {@link InetAddress} to use
     */
    public DefaultDnsOptEcsRecord(int maxPayladSize, int srcPrefixLength, InetAddress address) {
        this(maxPayladSize, 0, 0, srcPrefixLength, address);
    }

    /**
     * Creates a new instance.
     *
     * @param maxPayladSize the suggested max payload size in bytes
     * @param protocolFamily the {@link InternetProtocolFamily} to use. This should be the same as the one used to
     *                       send the query.
     */
    public DefaultDnsOptEcsRecord(int maxPayladSize, InternetProtocolFamily protocolFamily) {
        this(maxPayladSize, 0, 0, 0, address(protocolFamily));
    }

    private static InetAddress address(InternetProtocolFamily family) {
        switch (family) {
            case IPv4:
                return NetUtil.LOCALHOST4;
            case IPv6:
                return NetUtil.LOCALHOST6;
            default:
                throw new Error();
        }
    }
    @Override
    public int sourcePrefixLength() {
        return srcPrefixLength;
    }

    @Override
    public int scopePrefixLength() {
        return 0;
    }

    @Override
    public InetAddress address() {
        return address;
    }
}
