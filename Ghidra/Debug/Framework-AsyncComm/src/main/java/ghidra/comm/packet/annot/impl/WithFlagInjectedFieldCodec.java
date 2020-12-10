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
import ghidra.comm.packet.annot.SizedByField;
import ghidra.comm.packet.annot.WithFlag;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.util.BitmaskSet;

/**
 * The {@link FieldCodec} for fields referred to by {@link SizedByField}
 * 
 * @see WithFlagWrapperFactory
 * @see WithFlagInjectionFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain. Must be a {@link BitmaskSet}
 */
public class WithFlagInjectedFieldCodec<ENCBUF, DECBUF, T>
		extends AbstractFieldCodec<ENCBUF, DECBUF, T> {

	private final Field controlledField;
	@SuppressWarnings("rawtypes")
	private final Enum flag;
	private final FieldCodec<ENCBUF, DECBUF, T> chainNext;
	private WithFlag.Mode mode;

	public WithFlagInjectedFieldCodec(Class<? extends Packet> pktType, Field field,
			Field controlledField, @SuppressWarnings("rawtypes") Enum flag, WithFlag.Mode mode,
			FieldCodec<ENCBUF, DECBUF, T> chainNext) {
		super(pktType, field);
		this.controlledField = controlledField;
		this.flag = flag;
		this.mode = mode;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return chainNext.decodeField(pkt, buf, count, factory);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		try {
			Object controlledValue = controlledField.get(pkt);
			BitmaskSet bs = (BitmaskSet) field.get(pkt); // val will not be updated if null
			if (bs == null) {
				bs = new BitmaskSet(flag.getClass());
				field.set(pkt, bs);
			}
			if ((controlledValue != null) ^ (mode != WithFlag.Mode.PRESENT)) {
				bs.add(flag);
			}
			else {
				bs.remove(flag);
			}
			chainNext.encodeField(buf, pkt, (T) bs);
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new AssertionError("INTERNAL:", e);
		}
	}
}
