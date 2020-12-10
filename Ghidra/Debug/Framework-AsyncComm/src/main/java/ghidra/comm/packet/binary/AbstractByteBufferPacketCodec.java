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

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.nio.*;
import java.nio.charset.*;

import ghidra.comm.packet.AbstractPacketCodec;
import ghidra.comm.packet.Packet;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.packet.fields.WrapperFactory;

/**
 * A codec for encoding packets as binary
 * 
 * These codecs encode integers in two's complement, floating-point numbers in IEEE 754, characters
 * in UTF-16, strings in UTF-8, enums as ordinals, and byte buffers as is. They employ
 * {@link ByteBuffer} for encoding and decoding.
 *
 * @param <T> the type of encoded packets
 */
public abstract class AbstractByteBufferPacketCodec<T>
		extends AbstractPacketCodec<T, ByteBuffer, ByteBuffer> {

	/**
	 * Decode a byte array
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param count the number of byte to decode, or null for unlimited
	 * @return the decoded value
	 */
	protected byte[] decodeByteArray(Field field, ByteBuffer buf, Integer count) {
		byte[] result = new byte[count == null ? buf.remaining() : count];
		buf.get(result);
		return result;
	}

	/**
	 * Encode a byte array
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 */
	protected void encodeByteArray(ByteBuffer buf, Field field, byte[] val) {
		buf.put(val);
	}

	/**
	 * Decode a character sequence using the given character set
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param count the number of characters to decode, or null for unlimited
	 * @param charset the character set to use to decode bytes to characters
	 * @return the decoded value
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	public CharSequence decodeCharSequence(Field field, ByteBuffer buf, Integer count,
			Charset charset) throws IOException {
		CharsetDecoder cd = charset.newDecoder();
		if (count == null) {
			return cd.decode(buf).toString();
		}
		CharBuffer out = CharBuffer.allocate(count.intValue());
		cd.decode(buf, out, true);
		out.flip();
		return out.toString();
	}

	/**
	 * Encode a character sequence using the given character set
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param charset the character set to use to encode characters to bytes
	 */
	public void encodeCharSequence(ByteBuffer buf, Field field, CharSequence val, Charset charset) {
		CharsetEncoder ce = charset.newEncoder();
		if (ce.encode(CharBuffer.wrap(val), buf, true) == CoderResult.OVERFLOW) {
			throw new BufferOverflowException();
		}
	}

	@Override
	public void appendEncoded(ByteBuffer into, ByteBuffer from) throws IOException {
		into.put(from);
	}

	@Override
	public boolean decodeBoolean(Field field, ByteBuffer buf)
			throws IOException, PacketDecodeException {
		return buf.get() != 0;
	}

	@Override
	public byte decodeByte(Field field, ByteBuffer buf) throws IOException, PacketDecodeException {
		return buf.get();
	}

	@Override
	public char decodeChar(Field field, ByteBuffer buf) throws IOException, PacketDecodeException {
		return buf.getChar();
	}

	@Override
	public short decodeShort(Field field, ByteBuffer buf)
			throws IOException, PacketDecodeException {
		return buf.getShort();
	}

	@Override
	public int decodeInt(Field field, ByteBuffer buf) throws IOException, PacketDecodeException {
		return buf.getInt();
	}

	@Override
	public long decodeLong(Field field, ByteBuffer buf) throws IOException, PacketDecodeException {
		return buf.getLong();
	}

	@Override
	public float decodeFloat(Field field, ByteBuffer buf)
			throws IOException, PacketDecodeException {
		return buf.getFloat();
	}

	@Override
	public double decodeDouble(Field field, ByteBuffer buf)
			throws IOException, PacketDecodeException {
		return buf.getDouble();
	}

	@Override
	public CharSequence decodeCharSequence(Field field, ByteBuffer buf, Integer count)
			throws IOException, PacketDecodeException {
		return decodeCharSequence(field, buf, count, Charset.defaultCharset());
	}

	@Override
	public <E extends Enum<E>> E decodeEnumConstant(Field field, ByteBuffer buf, Class<E> type)
			throws IOException, PacketDecodeException {
		E[] consts = type.getEnumConstants();
		int idx;
		if (consts.length <= 0x100) {
			idx = decodeByte(field, buf);
			if (idx < 0) {
				idx += 0x100;
			}
		}
		else if (consts.length <= 0x10000) {
			idx = decodeShort(field, buf);
			idx = decodeByte(field, buf);
			if (idx < 0) {
				idx += 0x10000;
			}
		}
		else {
			idx = decodeInt(field, buf);
		}
		if (idx >= 0 && idx < consts.length) {
			return consts[idx];
		}
		throw new PacketFieldValueMismatchException(field, "0 <= n < " + consts.length, idx);
	}

	@Override
	public void encodeBoolean(ByteBuffer buf, Field field, boolean val) {
		buf.put(val ? (byte) 1 : 0);
	}

	@Override
	public void encodeByte(ByteBuffer buf, Field field, byte val)
			throws IOException, PacketEncodeException {
		buf.put(val);
	}

	@Override
	public void encodeChar(ByteBuffer buf, Field field, char val)
			throws IOException, PacketEncodeException {
		buf.putChar(val);
	}

	@Override
	public void encodeShort(ByteBuffer buf, Field field, short val)
			throws IOException, PacketEncodeException {
		buf.putShort(val);
	}

	@Override
	public void encodeInt(ByteBuffer buf, Field field, int val)
			throws IOException, PacketEncodeException {
		buf.putInt(val);
	}

	@Override
	public void encodeLong(ByteBuffer buf, Field field, long val)
			throws IOException, PacketEncodeException {
		buf.putLong(val);
	}

	@Override
	public void encodeFloat(ByteBuffer buf, Field field, float val)
			throws IOException, PacketEncodeException {
		buf.putFloat(val);
	}

	@Override
	public void encodeDouble(ByteBuffer buf, Field field, double val)
			throws IOException, PacketEncodeException {
		buf.putDouble(val);
	}

	@Override
	public void encodeCharSequence(ByteBuffer buf, Field field, CharSequence val)
			throws IOException, PacketEncodeException {
		encodeCharSequence(buf, field, val, Charset.defaultCharset());
	}

	@Override
	public void encodeEnumConstant(ByteBuffer buf, Field field, Enum<?> val)
			throws IOException, PacketEncodeException {
		int max = val.getClass().getEnumConstants().length;
		if (max <= 0x100) {
			encodeByte(buf, field, (byte) val.ordinal());
		}
		else if (max <= 0x100000) {
			encodeShort(buf, field, (short) val.ordinal());
		}
		else {
			encodeInt(buf, field, val.ordinal());
		}
	}

	@Override
	public WrapperFactory<ByteBuffer, ByteBuffer> getFactoryForAnnotation(
			Class<? extends Packet> pkt, Field field, Annotation annot) {
		if (annot.annotationType() == SequenceTerminated.class) {
			return new SequenceTerminatedWrapperFactory();
		}
		else if (annot.annotationType() == NullTerminated.class) {
			return new NullTerminatedWrapperFactory();
		}
		else if (annot.annotationType() == ReverseByteOrder.class) {
			return new ReverseByteOrderWrapperFactory();
		}
		return super.getFactoryForAnnotation(pkt, field, annot);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public <U> FieldCodec<ByteBuffer, ByteBuffer, U> getFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends U> fldType) {
		if (fldType == byte[].class) {
			return (FieldCodec<ByteBuffer, ByteBuffer, U>) new ByteArrayFieldCodec(this, pktType,
				field);
		}
		else if (fldType.isEnum()) {
			return new ByteBufferEnumFieldCodec(pktType, field, fldType, this);
		}
		return super.getFieldCodecForType(pktType, field, fldType);
	}

	@Override
	public int getDecodePosition(ByteBuffer buf) {
		return buf.position();
	}

	@Override
	public int limitDecodeBuffer(ByteBuffer buf, int len) {
		if (len > buf.capacity()) {
			throw new BufferUnderflowException();
		}
		int cur = buf.limit();
		buf.limit(len);
		return cur;
	}

	@Override
	public int measureDecodeRemaining(ByteBuffer buf) {
		return buf.remaining();
	}

	@Override
	public int measureEncodeSize(ByteBuffer buf) {
		return buf.position();
	}

	@Override
	public void setDecodePosition(ByteBuffer buf, int position) {
		buf.position(position);
	}

	@Override
	public void setEncodePosition(ByteBuffer buf, int pos) {
		buf.position(pos);
	}
}
