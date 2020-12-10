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
package ghidra.comm.packet.annot.impl;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Set;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.binary.AbstractByteBufferPacketCodec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.util.BitmaskSet;

/**
 * The {@link FieldCodec} for encoding {@link BitmaskSet} values for
 * {@link AbstractByteBufferPacketCodec}
 * 
 * This simply encodes the set using the bitmask encoding provided by the set. To use this codec,
 * the field should be declared as {@link BitmaskSet}, not just {@link Set}.
 */
public class BitmaskEncodedFieldCodec<ENCBUF, DECBUF>
		extends AbstractFieldCodec<ENCBUF, DECBUF, BitmaskSet<?>> {

	private final Class<?> universe;
	private final Class<? extends Number> encType;
	private final FieldCodec<ENCBUF, DECBUF, Number> chainNext;

	public BitmaskEncodedFieldCodec(Class<? extends Packet> pktType, Field field, Class<?> universe,
			Class<? extends Number> encType, FieldCodec<ENCBUF, DECBUF, Number> chainNext) {
		super(pktType, field);
		this.universe = universe;
		this.encType = encType;
		this.chainNext = chainNext;
	}

	@Override
	public BitmaskSet<?> decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		Number bits = chainNext.decodeField(pkt, buf, null, factory);
		@SuppressWarnings({ "unchecked", "rawtypes" })
		BitmaskSet val = new BitmaskSet(universe, bits.longValue());
		return val;
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, BitmaskSet<?> val)
			throws IOException, PacketEncodeException {
		long bits = val.getBitmask();
		Number enc = getIntegralOfType(encType, bits);
		chainNext.encodeField(buf, pkt, enc);
	}
}
