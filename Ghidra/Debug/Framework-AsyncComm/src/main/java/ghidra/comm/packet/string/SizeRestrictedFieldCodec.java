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

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.packet.string.SizeRestricted.PadDirection;

/**
 * The {@link FieldCodec} for fields annotated by {@link SizeRestricted}
 *
 * @see SizeRestrictedWrapperFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 */
public class SizeRestrictedFieldCodec<ENCBUF, DECBUF, T>
		extends AbstractFieldCodec<ENCBUF, DECBUF, T> {
	private final int min;
	private final int max;
	private final SizeRestricted annot;
	private final PacketCodecInternal<?, ENCBUF, DECBUF> codec;
	private final FieldCodec<ENCBUF, DECBUF, T> chainNext;
	private final FieldCodec<ENCBUF, DECBUF, Character> chainChar;

	public SizeRestrictedFieldCodec(Class<? extends Packet> pktType, Field field, int min, int max,
			SizeRestricted annot, PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			FieldCodec<ENCBUF, DECBUF, T> chainNext,
			FieldCodec<ENCBUF, DECBUF, Character> chainChar) {
		super(pktType, field);
		this.max = max;
		this.min = min;
		this.annot = annot;
		this.codec = codec;
		this.chainNext = chainNext;
		this.chainChar = chainChar;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		int pos = codec.getDecodePosition(buf);
		int orig = codec.limitDecodeBuffer(buf, pos + max);
		T result = chainNext.decodeField(pkt, buf, count, factory);
		if (codec.measureDecodeRemaining(buf) != 0) {
			throw new PacketDecodeException("Gratuitous data in size-restricted field: " + buf);
			// TODO: Consider: it might be padding...
		}
		codec.limitDecodeBuffer(buf, orig);
		return result;
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		ENCBUF part = codec.newEncodeBuffer();
		chainNext.encodeField(part, pkt, val);
		long len = codec.measureEncodeSize(part);
		if (len > max) {
			throw new PacketEncodeException("Encoding " + field + " exceeds its maximum size");
		}
		else if (len >= min) {
			codec.appendEncoded(buf, part);
		}
		else if (annot.direction() == PadDirection.LEFT) {
			for (int i = 0; i < min - len; i++) {
				chainChar.encodeField(buf, pkt, annot.pad());
			}
			codec.appendEncoded(buf, part);
		}
		else if (annot.direction() == PadDirection.RIGHT) {
			codec.appendEncoded(buf, part);
			for (int i = 0; i < min - len; i++) {
				chainChar.encodeField(buf, pkt, annot.pad());
			}
		}
		else {
			throw new PacketEncodeException(
				"Encoding " + field + " fails to meet its minimum size");
		}
	}
}
