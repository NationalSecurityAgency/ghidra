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
package ghidra.program.model.data;

import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.lang.Endian;
import ghidra.util.StringUtilities;
import ghidra.util.exception.UsrException;

/**
 * A parser to invert {@link StringDataInstance#getStringRepresentation()},
 * {@link StringDataInstance#getCharRepresentation()}, and related.
 */
public class StringRenderParser {

	private static String hexDigits = "0123456789ABCDEFabcdef";

	/**
	 * An exception for when a string representation cannot be parsed.
	 */
	public static class StringParseException extends UsrException {
		public StringParseException(int pos, Set<Character> expected, char got) {
			super("Error parsing string representation at position " + pos + ". Expected one of " +
				Objects.requireNonNull(expected) + " but got " + got);
		}

		public StringParseException(int pos) {
			super("Unexpected end of string representation at position " + pos + ".");
		}
	}

	private enum State {
		INIT(true, "uU'\"" + hexDigits),
		PREFIX(false, "8'\"" + hexDigits),
		UNIT(true, "'\"" + hexDigits),
		STR(false),
		BYTE(false, hexDigits),
		BYTE_SUFFIX(false, "h"),
		COMMA(true, ","),
		ESCAPE(false, "0abtnvfr\\\"'xuU"),
		CODE_POINT(false, hexDigits);

		private final boolean isFinal;
		private final Set<Character> accepts;

		private State(boolean isFinal) { // Implies this accepts any
			this.isFinal = isFinal;
			this.accepts = null;
		}

		private State(boolean isFinal, String accepts) {
			this(isFinal, accepts.chars()
					.mapToObj(i -> (char) i)
					.collect(Collectors.toSet()));
		}

		private State(boolean isFinal, Set<Character> accepts) {
			this.isFinal = isFinal;
			this.accepts = Collections.unmodifiableSet(accepts);
		}

		private void checkAccepts(int pos, char c) throws StringParseException {
			if (accepts == null) {
				return;
			}
			if (accepts.contains(c)) {
				return;
			}
			throw new StringParseException(pos, accepts, c);
		}

		private void checkFinal(int pos) throws StringParseException {
			if (isFinal) {
				return;
			}
			throw new StringParseException(pos);
		}
	}

	private final char quoteChar;
	private final Endian endian;
	private final String charsetName;
	private final boolean includeBOM;
	private final CharBuffer oneCodePointBuffer = CharBuffer.allocate(2);

	private int pos; // total characters consumed, not just of current buffer
	private State state;
	private Charset charset;
	private CharsetEncoder encoder;
	private int val;
	private int codeDigits;

	/**
	 * Construct a parser
	 * 
	 * @param quoteChar the character expected to enclose the representation. Use double quote (")
	 *            for strings. Use single quote (') for characters.
	 * @param endian the endian for unicode strings
	 * @param charsetName the character set name, as in {@link Charset#forName(String)}
	 * @param includeBOM true to prepend a byte order marker, if applicable
	 */
	public StringRenderParser(char quoteChar, Endian endian, String charsetName,
			boolean includeBOM) {
		this.quoteChar = Objects.requireNonNull(quoteChar);
		this.endian = Objects.requireNonNull(endian);
		this.charsetName = charsetName;
		this.includeBOM = includeBOM;

		reset();
	}

	/**
	 * Reset the parser
	 */
	public void reset() {
		pos = 0;
		state = State.INIT;
		val = 0;

		charset = null;
		encoder = null;
	}

	protected void initCharset(ByteBuffer out, String reprCharsetName) {
		String charsetName = this.charsetName != null ? this.charsetName : reprCharsetName;
		int charSize = CharsetInfo.getInstance().getCharsetCharSize(charsetName);
		if (CharsetInfo.isBOMCharset(charsetName)) {
			// Take care of the BOM ourselves, because it must be first, before any initial bytes
			charsetName += endian.isBigEndian() ? "BE" : "LE";
		}
		charset = Charset.forName(charsetName);
		if (includeBOM) {
			if (charSize == 2) {
				out.putShort((short) StringUtilities.UNICODE_BE_BYTE_ORDER_MARK);
			}
			else if (charSize == 4) {
				out.putInt(StringUtilities.UNICODE_BE_BYTE_ORDER_MARK);
			}
		}
		encoder = charset.newEncoder();
	}

	protected int valHexDigit(char c) {
		if ('0' <= c && c <= '9') {
			return c - '0' + 0;
		}
		if ('A' <= c && c <= 'F') {
			return c - 'A' + 0xA;
		}
		if ('a' <= c && c <= 'f') {
			return c - 'a' + 0xa;
		}
		throw new AssertionError();
	}

	protected State parseCharInit(ByteBuffer out, char c) {
		if (c == 'u') {
			return State.PREFIX;
		}
		if (c == 'U') {
			initCharset(out, CharsetInfo.UTF32);
			return State.UNIT;
		}
		initCharset(out, CharsetInfo.USASCII);
		return parseCharUnit(out, c);
	}

	protected State parseCharPrefix(ByteBuffer out, char c) {
		if (c == '8') {
			initCharset(out, CharsetInfo.UTF8);
			return State.UNIT;
		}
		initCharset(out, CharsetInfo.UTF16);
		return parseCharUnit(out, c);
	}

	protected State parseCharUnit(ByteBuffer out, char c) {
		if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f')) {
			val = valHexDigit(c);
			return State.BYTE;
		}
		if (c == quoteChar) {
			return State.STR;
		}
		throw new AssertionError();
	}

	protected void encodeCodePoint(ByteBuffer out, int cp)
			throws MalformedInputException, UnmappableCharacterException {
		if (!Character.isSupplementaryCodePoint(cp)) {
			encodeChar(out, (char) cp);
			return;
		}
		oneCodePointBuffer.clear();
		oneCodePointBuffer.put(0, Character.highSurrogate(cp));
		oneCodePointBuffer.put(1, Character.lowSurrogate(cp));
		encodeBufferedCodePoint(out);
	}

	protected void encodeChar(ByteBuffer out, char c)
			throws MalformedInputException, UnmappableCharacterException {
		oneCodePointBuffer.clear();
		oneCodePointBuffer.put(0, c);
		oneCodePointBuffer.limit(1);
		encodeBufferedCodePoint(out);
	}

	protected void encodeBufferedCodePoint(ByteBuffer out)
			throws MalformedInputException, UnmappableCharacterException {
		CoderResult cr = encoder.encode(oneCodePointBuffer, out, false);
		if (cr.isOverflow()) {
			throw new BufferOverflowException();
		}
		if (cr.isMalformed()) {
			throw new MalformedInputException(1);
		}
		if (cr.isUnmappable()) {
			throw new UnmappableCharacterException(1);
		}
	}

	protected State parseCharStr(ByteBuffer out, char c)
			throws MalformedInputException, UnmappableCharacterException {
		if (c == quoteChar) {
			return State.COMMA;
		}
		if (c == '\\') {
			return State.ESCAPE;
		}
		encodeChar(out, c);
		return State.STR;
	}

	protected State parseCharByte(ByteBuffer out, char c) {
		val = (val << 4) + valHexDigit(c);
		return State.BYTE_SUFFIX;
	}

	protected State parseCharByteSuffix(ByteBuffer out, char c) {
		if (c == 'h') {
			out.put((byte) val);
			val = 0;
			return State.COMMA;
		}
		throw new AssertionError();
	}

	protected State parseCharComma(ByteBuffer out, char c) {
		if (c == ',') {
			return State.UNIT;
		}
		throw new AssertionError();
	}

	protected State parseCharEscape(ByteBuffer out, char c)
			throws MalformedInputException, UnmappableCharacterException {
		switch (c) {
			case '0':
				encodeChar(out, '\0');
				return State.STR;
			case 'a':
				encodeChar(out, (char) 7);
				return State.STR;
			case 'b':
				encodeChar(out, '\b');
				return State.STR;
			case 't':
				encodeChar(out, '\t');
				return State.STR;
			case 'n':
				encodeChar(out, '\n');
				return State.STR;
			case 'v':
				encodeChar(out, (char) 11);
				return State.STR;
			case 'f':
				encodeChar(out, '\f');
				return State.STR;
			case 'r':
				encodeChar(out, '\r');
				return State.STR;
			case '\\':
				encodeChar(out, '\\');
				return State.STR;
			case '\"':
				encodeChar(out, '"');
				return State.STR;
			case '\'':
				encodeChar(out, '\'');
				return State.STR;
			case 'x':
				codeDigits = 2;
				return State.CODE_POINT;
			case 'u':
				codeDigits = 4;
				return State.CODE_POINT;
			case 'U':
				codeDigits = 8;
				return State.CODE_POINT;
			default:
				throw new AssertionError();
		}
	}

	protected State parseCharCodePoint(ByteBuffer out, char c)
			throws MalformedInputException, UnmappableCharacterException {
		assert codeDigits > 0;
		val = (val << 4) + valHexDigit(c);
		if (0 == (--codeDigits)) {
			encodeCodePoint(out, val);
			return State.STR;
		}
		return State.CODE_POINT;
	}

	protected State parseChar(ByteBuffer out, char c)
			throws MalformedInputException, UnmappableCharacterException {
		switch (state) {
			case INIT:
				return parseCharInit(out, c);
			case PREFIX:
				return parseCharPrefix(out, c);
			case UNIT:
				return parseCharUnit(out, c);
			case STR:
				return parseCharStr(out, c);
			case BYTE:
				return parseCharByte(out, c);
			case BYTE_SUFFIX:
				return parseCharByteSuffix(out, c);
			case COMMA:
				return parseCharComma(out, c);
			case ESCAPE:
				return parseCharEscape(out, c);
			case CODE_POINT:
				return parseCharCodePoint(out, c);
			default:
				throw new AssertionError();
		}
	}

	/**
	 * Parse and encode a complete string or character representation
	 * 
	 * @param in the buffer containing the representation
	 * @return a buffer containing the encoded string or character
	 * @throws StringParseException if the representation could not be parsed
	 * @throws MalformedInputException if a character sequence in the representation is not valid
	 * @throws UnmappableCharacterException if a character cannot be encoded
	 */
	public ByteBuffer parse(CharBuffer in)
			throws StringParseException, MalformedInputException, UnmappableCharacterException {
		int bufSize = in.remaining() * 2; // We don't know the charset, yet.
		while (true) {
			ByteBuffer out = ByteBuffer.allocate(bufSize)
					.order(endian == Endian.BIG ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
			int pos = in.position();
			try {
				parse(out, in);
				finish(out);
				out.flip();
				return out;
			}
			catch (BufferOverflowException e) {
				bufSize <<= 1;
				in.position(pos);
				reset();
			}
		}
	}

	/**
	 * Parse and encode a portion of a string or character representation
	 * 
	 * @param out the destination buffer for the encoded string or character, having matching byte
	 *            order to the charset.
	 * @param in the source buffer for the representation
	 * @throws StringParseException if the representation could not be parsed
	 * @throws MalformedInputException if a character sequence in the representation is not valid
	 * @throws UnmappableCharacterException if a character cannot be encoded
	 */
	public void parse(ByteBuffer out, CharBuffer in)
			throws StringParseException, MalformedInputException, UnmappableCharacterException {
		try {
			while (in.hasRemaining()) {
				char c = in.get();
				state.checkAccepts(pos, c);
				state = parseChar(out, c);
				pos++;
			}
		}
		catch (Throwable e) {
			in.position(in.position() - 1);
			throw e;
		}
	}

	/**
	 * Finish parsing and encoded a string or character representation
	 * 
	 * @param out the destination buffer for the encoded string or character
	 * @throws StringParseException if the representation is not complete
	 */
	public void finish(ByteBuffer out) throws StringParseException {
		state.checkFinal(pos);
	}
}
