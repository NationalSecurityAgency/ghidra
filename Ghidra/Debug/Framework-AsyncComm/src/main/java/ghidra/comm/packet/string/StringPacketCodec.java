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

import java.io.EOFException;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.CharBuffer;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.google.common.primitives.UnsignedInteger;
import com.google.common.primitives.UnsignedLong;

import ghidra.comm.packet.AbstractPacketCodec;
import ghidra.comm.packet.Packet;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.packet.fields.WrapperFactory;

/**
 * A codec for encoding packets as text
 */
public class StringPacketCodec extends AbstractPacketCodec<String, StringBuilder, CharBuffer> {
	public static final StringPacketCodec INSTANCE = new StringPacketCodec();
	public static final int DEFAULT_RADIX = 16;

	protected final static String RADIX_DIGS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	protected static final BigInteger LONG_MODULUS =
		new BigInteger(1, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0 });

	protected static final String _RE_DIGITS = "(\\p{Digit}+)";
	protected static final String _RE_HEX_DIGITS = "(\\p{XDigit}+)";
	// an exponent is 'e' or 'E' followed by a signed decimal integer.
	protected static final String _RE_EXPONENT = "[eE][+-]?" + _RE_DIGITS;
	/** This was taken from the documentation in {@link Double#valueOf(String)} */
	protected static final Pattern RE_FLOATING_POINT = Pattern.compile( //
		"[+-]?(" + // Optional sign character
			"NaN|" +           // "NaN" string
			"Infinity|" +      // "Infinity" string

			// A decimal floating-point string representing a finite positive
			// number without a leading sign has at most five basic pieces:
			// Digits . Digits ExponentPart FloatTypeSuffix
			//
			// Since this method allows integer-only strings as input
			// in addition to strings of floating-point literals, the
			// two sub-patterns below are simplifications of the grammar
			// productions from section 3.10.2 of
			// The Java Language Specification.

			// Digits ._opt Digits_opt ExponentPart_opt FloatTypeSuffix_opt
			"(((" + _RE_DIGITS + "(\\.)?(" + _RE_DIGITS + "?)(" + _RE_EXPONENT + ")?)|" +

			// . Digits ExponentPart_opt FloatTypeSuffix_opt
			"(\\.(" + _RE_DIGITS + ")(" + _RE_EXPONENT + ")?)|" +

			// Hexadecimal strings
			"((" +
			// 0[xX] HexDigits ._opt BinaryExponent FloatTypeSuffix_opt
			"(0[xX]" + _RE_HEX_DIGITS + "(\\.)?)|" +

			// 0[xX] HexDigits_opt . HexDigits BinaryExponent FloatTypeSuffix_opt
			"(0[xX]" + _RE_HEX_DIGITS + "?(\\.)" + _RE_HEX_DIGITS + ")" +

			")[pP][+-]?" + _RE_DIGITS + "))" + "[fFdD]?))" //
	);

	/**
	 * Get the singleton instance of this codec
	 * 
	 * @return the instance
	 */
	public static StringPacketCodec getInstance() {
		return INSTANCE;
	}

	/**
	 * Compute the maximum number of characters needed to represent a numeric type
	 * 
	 * Computes the number of characters needed to encode the maximum value of a numeric type stored
	 * in the given number of bytes. The number is encoded by converting the value to a string using
	 * the given radix. For example, the maximum number of characters needed to store a two-byte
	 * integer in base 10 is 5, based on the maximum encoded value: {@code "65535"}.
	 * 
	 * @param radix the radix for text encoding
	 * @param byteCount the number of bytes in the primitive type
	 * @return the maximum number of characters need to encode the type
	 */
	protected static int computeMaxChars(int radix, int byteCount) {
		if (radix == 16) {
			return byteCount * 2;
		}
		double charsPerByte = 8 / (Math.log(radix / Math.log(2)));
		double chars = byteCount * charsPerByte;
		return (int) Math.ceil(chars);
	}

	/**
	 * Construct a regular expression to recognize textual numbers of a given radix
	 * 
	 * @see Long#parseLong(String, int)
	 * 
	 * @param radix the radix
	 * @return the regular expression
	 */
	protected static Pattern makeNumericPattern(int radix) {
		if (radix < 2 || radix > 36) {
			throw new IllegalArgumentException("Radix must be between 2 and 36");
		}
		String digs = RADIX_DIGS.substring(0, radix);
		if (radix > 10) {
			digs += RADIX_DIGS.substring(10, radix).toLowerCase();
		}
		return Pattern.compile("[+-]?[" + digs + "]+");
	}

	/**
	 * Read as many characters from the buffer that match the format of a floating-point value
	 * 
	 * @param buf the buffer
	 * @return the prefix matching the format
	 * @throws InvalidPacketException if no prefix matches the format
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	protected static String readFloatingPoint(CharBuffer buf) throws InvalidPacketException {
		return readString(buf, null, RE_FLOATING_POINT);
	}

	/**
	 * Read as many characters from the buffer that match the format of an integer
	 * 
	 * @param buf the buffer
	 * @param radix the radix of the expected value
	 * @param bytes the number of bytes in the primitive integer type
	 * @return the prefix matching the format
	 * @throws InvalidPacketException if no prefix matches the format
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	protected static String readNumericString(CharBuffer buf, int radix, int bytes)
			throws InvalidPacketException {
		return readString(buf, computeMaxChars(radix, bytes), makeNumericPattern(radix));
	}

	/**
	 * Read a given number of characters from the buffer
	 * 
	 * @param buf the buffer
	 * @param count the number of characters, or null for all remaining characters
	 * @return the prefix
	 * @throws IOException if there is an issue accessing a device or buffer
	 */
	protected static String readString(CharBuffer buf, Integer count) {
		try {
			return readString(buf, count, null);
		}
		catch (InvalidPacketException e) {
			throw new AssertionError("INTERNAL");
		}
	}

	/**
	 * Read as many characters from the buffer that match a given pattern
	 * 
	 * @param buf the buffer
	 * @param count the maximum number of characters, or null for unlimited
	 * @param pat the pattern to match
	 * @return the prefix matching the pattern
	 * @throws InvalidPacketException if no prefix matches the pattern
	 * @throws EOFException
	 */
	protected static String readString(CharBuffer buf, Integer count, Pattern pat)
			throws InvalidPacketException {
		CharBuffer sub = buf;
		if (count != null) {
			count = Math.min(count, buf.remaining());
			sub = buf.subSequence(0, count.intValue());
		}
		if (pat != null) {
			Matcher mat = pat.matcher(sub);
			if (mat.matches()) {
				count = buf.remaining();
			}
			else if (mat.lookingAt()) {
				count = mat.end();
			}
			else if (!buf.hasRemaining()) {
				throw new BufferUnderflowException();
			}
			else {
				throw new InvalidPacketException(
					"Field '" + buf + "' does not follow expected pattern: " + pat);
			}
		}
		if (count != null) {
			sub = buf.subSequence(0, count);
			buf.position(buf.position() + count);
			return sub.toString();
		}
		String ret = buf.toString();
		buf.position(buf.limit());
		return ret;
	}

	/**
	 * A map of enum names to enum values, listing the longest names first
	 * 
	 * This is a map of maps. The first tier maps enum types. The second tier maps the constant
	 * names from each enum type to the actual constant value. The longest name is listed first so
	 * that if one name is a prefix of another in the same {@code enum}, the longest match is taken.
	 */
	protected Map<Class<Enum<?>>, LinkedHashMap<String, Enum<?>>> longestNamesByEnumClass =
		LazyMap.lazyMap(new HashMap<>(), (Class<Enum<?>> enumType) -> {
			List<Pair<String, Enum<?>>> longestFirst = new ArrayList<>();
			if (CustomNamedEnum.class.isAssignableFrom(enumType)) {
				for (Enum<?> e : enumType.getEnumConstants()) {
					CustomNamedEnum c = (CustomNamedEnum) e;
					longestFirst.add(new ImmutablePair<>(c.getCustomName(), e));
				}
			}
			else {
				for (Enum<?> e : enumType.getEnumConstants()) {
					longestFirst.add(new ImmutablePair<>(e.name(), e));
				}
			}
			longestFirst.sort((Pair<String, Enum<?>> p1,
					Pair<String, Enum<?>> p2) -> p2.getKey().length() - p1.getKey().length());
			LinkedHashMap<String, Enum<?>> result = new LinkedHashMap<>();
			for (Pair<String, Enum<?>> p : longestFirst) {
				result.put(p.getKey(), p.getValue());
			}
			return result;
		});

	protected StringPacketCodec() {
	}

	/**
	 * Decode a byte value in the given radix
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param radix the radix
	 * @return the decoded value
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public byte decodeByte(Field field, CharBuffer buf, int radix) throws PacketDecodeException {
		String part = readNumericString(buf, radix, 1);
		try {
			return (byte) Short.parseShort(part, radix);
		}
		catch (NumberFormatException e) {
			throw new InvalidPacketException("Malformed byte", e);
		}
	}

	/**
	 * Decode a short integer value in the given radix
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param radix the radix
	 * @return the decoded value
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public short decodeShort(Field field, CharBuffer buf, int radix) throws PacketDecodeException {
		String part = readNumericString(buf, radix, 2);
		try {
			return (short) Integer.parseInt(part, radix);
		}
		catch (NumberFormatException e) {
			throw new InvalidPacketException("Malformed long", e);
		}
	}

	/**
	 * Decode an integer value in the given radix
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param radix the radix
	 * @return the decoded value
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public int decodeInt(Field field, CharBuffer buf, int radix) throws PacketDecodeException {
		String part = readNumericString(buf, radix, 4);
		try {
			return UnsignedInteger.valueOf(part, radix).intValue();
		}
		catch (NumberFormatException e) {
			throw new InvalidPacketException("Malformed int", e);
		}
	}

	/**
	 * Decode a long integer value in the given radix
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param radix the radix
	 * @return the decoded value
	 * @throws PacketDecodeException if the packet is not well formed
	 */
	public long decodeLong(Field field, CharBuffer buf, int radix) throws PacketDecodeException {
		String part = readNumericString(buf, radix, 8);
		try {
			return UnsignedLong.valueOf(part, radix).longValue();
		}
		catch (NumberFormatException e) {
			throw new InvalidPacketException("Malformed long", e);
		}
	}

	/**
	 * Decode a character array
	 * 
	 * @param field the field for which the value is decoded
	 * @param buf the buffer from which the value is decoded
	 * @param count the number of characters to decode; -1 for all remaining
	 * @return the decoded array
	 */
	public char[] decodeCharArray(Field field, CharBuffer buf, int count) {
		char[] ret;
		if (count == -1) {
			ret = new char[buf.remaining()];
		}
		else {
			ret = new char[count];
		}
		buf.get(ret);
		return ret;
	}

	/**
	 * Encode a byte value in the given radix
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param radix the radix
	 */
	public void encodeByte(StringBuilder buf, Field field, byte val, int radix) {
		buf.append(Integer.toString(val & 0x0ff, radix));
	}

	/**
	 * Encode a short integer value in the given radix
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param radix the radix
	 */
	public void encodeShort(StringBuilder buf, Field field, short val, int radix) {
		buf.append(Integer.toString(val & 0x0ffff, radix));
	}

	/**
	 * Encode an integer value in the given radix
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param radix the radix
	 */
	public void encodeInt(StringBuilder buf, Field field, int val, int radix) {
		buf.append(Long.toString(val & 0x0ffffffffL, radix));
	}

	/**
	 * Encode a long integer value in the given radix
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param radix the radix
	 */
	public void encodeLong(StringBuilder buf, Field field, long val, int radix) {
		if (val >= 0) {
			buf.append(Long.toString(val, radix));
		}
		else {
			BigInteger v = BigInteger.valueOf(val);
			v = v.add(LONG_MODULUS);
			buf.append(v.toString(radix));
		}
	}

	/**
	 * Encode a single-precision float value in decimal or hexadecimal
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param hex true to use hexadecimal, false to use decimal
	 */
	public void encodeFloat(StringBuilder buf, Field field, float val, boolean hex) {
		if (hex) {
			buf.append(Float.toHexString(val));
		}
		else {
			buf.append(val);
		}
	}

	/**
	 * Encode a double-precision float value in decimal or hexadecimal
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 * @param hex true to use hexadecimal, false to use decimal
	 */
	public void encodeDouble(StringBuilder buf, Field field, double val, boolean hex) {
		if (hex) {
			buf.append(Double.toHexString(val));
		}
		else {
			buf.append(val);
		}
	}

	/**
	 * Encode a character array
	 * 
	 * @param buf the buffer into which to append the encoded data
	 * @param field the field for which the value is encoded
	 * @param val the value to encode
	 */
	public void encodeCharArray(StringBuilder buf, Field field, char[] val) {
		buf.append(val);
	}

	@Override
	public boolean decodeBoolean(Field field, CharBuffer buf)
			throws IOException, PacketDecodeException {
		char zeroOne = buf.get();
		if (zeroOne == '0') {
			return false;
		}
		else if (zeroOne == '1') {
			return true;
		}
		else {
			throw new InvalidPacketException(
				"Expected boolean (1/0) for " + field + ". Got " + zeroOne);
		}
	}

	@Override
	public byte decodeByte(Field field, CharBuffer buf) throws IOException, PacketDecodeException {
		return decodeByte(field, buf, DEFAULT_RADIX);
	}

	@Override
	public char decodeChar(Field field, CharBuffer buf) throws IOException, PacketDecodeException {
		return buf.get();
	}

	@Override
	public short decodeShort(Field field, CharBuffer buf)
			throws IOException, PacketDecodeException {
		return decodeShort(field, buf, DEFAULT_RADIX);
	}

	@Override
	public int decodeInt(Field field, CharBuffer buf) throws IOException, PacketDecodeException {
		return decodeInt(field, buf, DEFAULT_RADIX);
	}

	@Override
	public long decodeLong(Field field, CharBuffer buf) throws IOException, PacketDecodeException {
		return decodeLong(field, buf, DEFAULT_RADIX);
	}

	@Override
	public float decodeFloat(Field field, CharBuffer buf)
			throws IOException, PacketDecodeException {
		String part = readFloatingPoint(buf);
		try {
			return Float.parseFloat(part);
		}
		catch (NumberFormatException e) {
			throw new InvalidPacketException("Malformed float", e);
		}
	}

	@Override
	public double decodeDouble(Field field, CharBuffer buf)
			throws IOException, PacketDecodeException {
		String part = readFloatingPoint(buf);
		try {
			return Double.parseDouble(part);
		}
		catch (NumberFormatException e) {
			throw new InvalidPacketException("Malformed double", e);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public <E extends Enum<E>> E decodeEnumConstant(Field field, CharBuffer buf, Class<E> type)
			throws IOException, PacketDecodeException {
		Map<String, Enum<?>> longestFirst = longestNamesByEnumClass.get(type);
		int pos = getDecodePosition(buf);
		String dec = "";
		for (Map.Entry<String, Enum<?>> ent : longestFirst.entrySet()) {
			setDecodePosition(buf, pos);
			String name = ent.getKey();
			int len = name.length();
			if (measureDecodeRemaining(buf) >= len) {
				dec = decodeCharSequence(field, buf, len);
				if (name.equals(dec)) {
					return (E) ent.getValue();
				}
			}
		}

		setDecodePosition(buf, pos);
		throw new PacketFieldValueMismatchException(field, longestFirst.keySet(), dec);
	}

	@Override
	public String decodeCharSequence(Field field, CharBuffer buf, Integer count)
			throws IOException, PacketDecodeException {
		return readString(buf, count == null ? null : count.intValue());
	}

	@Override
	public void encodeBoolean(StringBuilder buf, Field field, boolean val)
			throws IOException, PacketEncodeException {
		if (val) {
			buf.append('1');
		}
		else {
			buf.append('0');
		}
	}

	@Override
	public void encodeByte(StringBuilder buf, Field field, byte val)
			throws IOException, PacketEncodeException {
		encodeByte(buf, field, val, DEFAULT_RADIX);
	}

	@Override
	public void encodeChar(StringBuilder buf, Field field, char val) {
		buf.append(val);
	}

	@Override
	public void encodeShort(StringBuilder buf, Field field, short val) {
		encodeShort(buf, field, val, DEFAULT_RADIX);
	}

	@Override
	public void encodeInt(StringBuilder buf, Field field, int val) {
		encodeInt(buf, field, val, DEFAULT_RADIX);
	}

	@Override
	public void encodeLong(StringBuilder buf, Field field, long val) {
		encodeLong(buf, field, val, DEFAULT_RADIX);
	}

	@Override
	public void encodeFloat(StringBuilder buf, Field field, float val) {
		encodeFloat(buf, field, val, false);
	}

	@Override
	public void encodeDouble(StringBuilder buf, Field field, double val) {
		encodeDouble(buf, field, val, false);
	}

	@Override
	public void encodeEnumConstant(StringBuilder buf, Field field, Enum<?> val) {
		if (val instanceof CustomNamedEnum) {
			encodeCharSequence(buf, field, ((CustomNamedEnum) val).getCustomName());
		}
		else {
			encodeCharSequence(buf, field, val.name());
		}
	}

	@Override
	public void encodeCharSequence(StringBuilder buf, Field field, CharSequence val) {
		buf.append(val);
	}

	@Override
	public void encodePacket(String buf, Packet pkt) throws PacketEncodeException {
		throw new UnsupportedOperationException("Strings are immutable");
	}

	@Override
	public WrapperFactory<StringBuilder, CharBuffer> getFactoryForAnnotation(
			Class<? extends Packet> pkt, Field field, Annotation annot) {
		if (annot.annotationType() == RegexSeparated.class) {
			return new RegexSeparatedWrapperFactory<>();
		}
		else if (annot.annotationType() == RegexTerminated.class) {
			return new RegexTerminatedWrapperFactory();
		}
		else if (annot.annotationType() == SizeRestricted.class) {
			return new SizeRestrictedWrapperFactory<>();
		}
		else if (annot.annotationType() == WithRadix.class) {
			return new WithRadixWrapperFactory();
		}
		else if (annot.annotationType() == WithSign.class) {
			return new WithSignWrapperFactory();
		}
		return super.getFactoryForAnnotation(pkt, field, annot);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public <U> FieldCodec<StringBuilder, CharBuffer, U> getFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends U> fldType) {
		if (fldType == char[].class) {
			return (FieldCodec<StringBuilder, CharBuffer, U>) new CharArrayFieldCodec(this, pktType,
				field);
		}
		else if (fldType.isEnum()) {
			return new StringEnumFieldCodec(this, pktType, field, fldType);
		}
		return super.getFieldCodecForType(pktType, field, fldType);
	}

	@Override
	protected String finishEncode(StringBuilder buf) {
		return buf.toString();
	}

	@Override
	public void appendEncoded(StringBuilder into, StringBuilder from) throws IOException {
		into.append(from);
	}

	@Override
	public int getDecodePosition(CharBuffer buf) {
		return buf.position();
	}

	@Override
	public int limitDecodeBuffer(CharBuffer buf, int len) {
		int cur = buf.limit();
		buf.limit(len);
		return cur;
	}

	@Override
	public int measureDecodeRemaining(CharBuffer buf) {
		return buf.remaining();
	}

	@Override
	public int measureEncodeSize(StringBuilder buf) {
		return buf.length();
	}

	@Override
	public CharBuffer newDecodeBuffer(String data) {
		return CharBuffer.wrap(data);
	}

	@Override
	public StringBuilder newEncodeBuffer() {
		return new StringBuilder();
	}

	@Override
	public void setDecodePosition(CharBuffer buf, int pos) {
		buf.position(pos);
	}

	@Override
	public void setEncodePosition(StringBuilder buf, int pos) {
		buf.setLength(pos);
	}

	/**
	 * An interface for {@code enum}s to control their encoding
	 * 
	 * It's possible a protocol specifies some list of commands well suited for enumeration.
	 * However, the text of the commands may not be suitable as names in a Java {@code enum}. Some
	 * characters may not be legal in Java identifiers. Furthermore, coding standards usually
	 * require names in {@code UPPER_CASE_WITH_UNDERSCORES}. If an {@code enum} implements this
	 * interface, it can encode its values to something other than their names so long as each
	 * custom name is still unique within the enumeration.
	 */
	public static interface CustomNamedEnum {
		/**
		 * Get the custom name for encoding this enumeration constant
		 * 
		 * @return the custom name
		 */
		public String getCustomName();
	}
}
