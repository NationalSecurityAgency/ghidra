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
package ghidra.comm.packet.binary;

import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.util.NumericUtilities;

/**
 * The {@link FieldCodec} for fields annotated by {@link SequenceTerminated} or
 * {@link NullTerminated} for {@link ByteBufferPacketCodec}
 *
 * @see SequenceTerminatedWrapperFactory
 * @see NullTerminatedWrapperFactory
 *
 * @param <T> the type of the field as passed through the chain
 */
public final class SequenceTerminatedFieldCodec<T>
		extends AbstractFieldCodec<ByteBuffer, ByteBuffer, T> {
	private final Field condField;
	private final FieldCodec<ByteBuffer, ByteBuffer, T> chainNext;
	private byte[] tok;

	public SequenceTerminatedFieldCodec(Class<? extends Packet> pktType, Field field, byte[] tok,
			Field optField, FieldCodec<ByteBuffer, ByteBuffer, T> chainNext) {
		super(pktType, field);
		this.tok = tok;
		this.condField = optField;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, ByteBuffer buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		// Look ahead to find the token, then chop the buffer removing the token
		// NOTE: This probably shouldn't decode through the chain.
		// Part of the idea of the annotation is that certain codecs may ignore them.
		// I see no reason for, e.g., the string codec to insert 00 to "null terminate"

		int matchedLen = 0;
		int i;
		for (i = buf.position(); i < buf.limit() && matchedLen < tok.length; i++) {
			if (buf.get(i) == tok[matchedLen]) {
				matchedLen++;
			}
			else {
				matchedLen = 0;
			}
		}
		if (matchedLen != tok.length) {
			if (condField != null) {
				return chainNext.decodeField(pkt, buf, count, factory);
			}
			else if (!buf.hasRemaining()) {
				throw new EOFException("Buffer is empty");
			}
			else {
				throw new InvalidPacketException("Missing terminator sequence [" +
					NumericUtilities.convertBytesToString(tok, ":"));
			}
		}
		int orig = buf.limit();
		buf.limit(i - matchedLen);
		T result = chainNext.decodeField(pkt, buf, count, factory);
		if (buf.hasRemaining()) {
			throw new InvalidPacketException(field + " did not consume buffer " + buf);
		}
		buf.limit(orig);
		buf.position(buf.position() + tok.length);
		return result;
	}

	@Override
	public void encodeField(ByteBuffer buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		chainNext.encodeField(buf, pkt, val);
		try {
			if (condField == null || condField.get(pkt) != null) {
				buf.put(tok);
			}
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
}
