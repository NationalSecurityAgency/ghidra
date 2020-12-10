/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.dbg.sctl.client;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import org.junit.Test;

import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.binary.ByteBufferPacketCodec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.common.notify.AbstractSctlListsLibrariesEventNotification.PathBase;
import ghidra.dbg.sctl.protocol.common.notify.SctlEventNotify;
import ghidra.dbg.sctl.protocol.common.notify.SctlLoadNotification;
import ghidra.dbg.sctl.protocol.v2012base.x86.SctlX86Context;
import ghidra.dbg.sctl.protocol.v2012ext.SelSctl2012ExtPacket;
import ghidra.dbg.sctl.protocol.v2012ext.x86.linux.Sctl2012ExtLinuxX86Dialect;
import ghidra.util.NumericUtilities;

public class SctlPacketsTest {
	/*
	 * This one was giving me trouble. Decoding by hand seems to work.
	 */
	@Test
	public void testDecode2012BusLoadNotification()
			throws PacketDecodeException, PacketEncodeException {
		String hexStr = "" + //
			"10010000000000000300000000ffffff" + // ................
			"ffffffffff0004000000000000010000" + // ................
			"00000000000b000000000000002f7573" + // ............./us
			"722f62696e2f6464ffffffffffffffff" + // r/bin/dd........
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"00000000000000000000000000000000" + // ................
			"0000000000000000"; //                  ........
		ByteBuffer inbuf = ByteBuffer.wrap(NumericUtilities.convertStringToBytes(hexStr));
		inbuf.order(ByteOrder.LITTLE_ENDIAN);
		int len = (int) inbuf.getLong();
		assertEquals(272, inbuf.remaining());
		assertEquals(272, len);

		final PacketCodec<ByteBuffer> codec = ByteBufferPacketCodec.getInstance();
		PacketFactory factory = Sctl2012ExtLinuxX86Dialect.INSTANCE.getPacketFactory();
		factory.registerTypes(codec);

		AbstractSelSctlPacket rcvd =
			codec.decodePacket(AbstractSelSctlPacket.class, inbuf, factory);

		SelSctl2012ExtPacket exp = new SelSctl2012ExtPacket(0,
			new SctlEventNotify(-1,
				new SctlLoadNotification(
					Arrays.asList(new PathBase[] { new PathBase("/usr/bin/dd", -1) }),
					new SctlX86Context())));
		codec.encodePacket(exp); // Fill the auto fields

		assertEquals(exp, rcvd);
	}
}
