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
package ghidra.comm.packet.string;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.CharBuffer;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annotated by {@link WithSign}
 * 
 * @see WithSignWrapperFactory
 *
 * @param <T> the type of the field as passed through the chain
 */
public class WithSignFieldCodec<T> extends AbstractFieldCodec<StringBuilder, CharBuffer, T> {
	private final Class<? extends T> fldType;
	private final FieldCodec<StringBuilder, CharBuffer, T> chainNext;

	public WithSignFieldCodec(Class<? extends Packet> pktType, Field field,
			Class<? extends T> fldType, FieldCodec<StringBuilder, CharBuffer, T> chainNext) {
		super(pktType, field);
		this.fldType = fldType;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, CharBuffer buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		if (buf.charAt(0) == '-') {
			buf.get();
			long n = getIntegralValue(chainNext.decodeField(pkt, buf, count, factory));
			return getIntegralOfType(fldType, -n);
		}
		return chainNext.decodeField(pkt, buf, count, factory);
	}

	@Override
	public void encodeField(StringBuilder buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		long n = getIntegralValue(val);
		if (n < 0) {
			buf.append('-');
			chainNext.encodeField(buf, pkt, getIntegralOfType(fldType, -n));
		}
		else {
			chainNext.encodeField(buf, pkt, val);
		}
	}
}
