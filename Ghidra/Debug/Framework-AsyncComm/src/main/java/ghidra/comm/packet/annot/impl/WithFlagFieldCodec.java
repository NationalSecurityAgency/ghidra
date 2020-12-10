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

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.WithFlag;
import ghidra.comm.packet.annot.WithFlag.Mode;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.util.BitmaskSet;

/**
 * The {@link FieldCodec} for fields annotated by {@link WithFlag}
 * 
 * @see WithFlagWrapperFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 */
public class WithFlagFieldCodec<ENCBUF, DECBUF, T> extends AbstractFieldCodec<ENCBUF, DECBUF, T> {

	private final Field flagField;
	@SuppressWarnings("rawtypes")
	private final Enum flag;
	private final Mode mode;
	private final FieldCodec<ENCBUF, DECBUF, T> chainNext;

	public WithFlagFieldCodec(Class<? extends Packet> pktType, Field field, Field flagField,
			@SuppressWarnings("rawtypes") Enum flag, WithFlag.Mode mode,
			FieldCodec<ENCBUF, DECBUF, T> chainNext) {
		super(pktType, field);
		this.flagField = flagField;
		this.flag = flag;
		this.mode = mode;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		try {
			@SuppressWarnings("rawtypes")
			BitmaskSet bm = (BitmaskSet) flagField.get(pkt);
			if (bm.contains(flag) ^ mode != WithFlag.Mode.PRESENT) {
				return chainNext.decodeField(pkt, buf, count, factory);
			}
			return null;
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new AssertionError("INTERNAL:", e);
		}
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		if (val != null) {
			chainNext.encodeField(buf, pkt, val);
		}
	}
}
