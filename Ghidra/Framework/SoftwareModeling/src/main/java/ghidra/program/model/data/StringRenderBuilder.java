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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;

import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;
import ghidra.util.StringUtilities;

/**
 * Helper class used to build up a formatted (for human consumption) string representation returned
 * by Unicode and String data types.
 * <p>
 * Call {@link #build()} to retrieve the formatted string.
 * <p>
 * Example (quotes are part of result): {@code "Test\tstring",01h,02h,"Second\npart"}
 *
 */
public class StringRenderBuilder {
	public static final char DOUBLE_QUOTE = '"';
	public static final char SINGLE_QUOTE = '\'';
	private static final int MAX_ASCII = 0x80;

	private final StringBuilder sb = new StringBuilder();
	private final int charSize;
	private final boolean utfCharset;
	private final char quoteChar;
	private boolean byteMode = true;

	public StringRenderBuilder(boolean utfCharset, int charSize) {
		this(utfCharset, charSize, DOUBLE_QUOTE);
	}

	public StringRenderBuilder(boolean utfCharset, int charSize, char quoteChar) {
		this.charSize = charSize;
		this.utfCharset = utfCharset;
		this.quoteChar = quoteChar;
	}

	/**
	 * Add a unicode codepoint as its escaped hex value, with a escape character
	 * prefix of 'x', 'u' or 'U' depending on the magnitude of the codePoint value.
	 * <p>
	 * {@literal codePoint 15 -> '\' 'x' "0F"}<br>
	 * {@literal codePoint 65535 -> '\' 'u' "FFFF"}<br>
	 * {@literal codePoint 65536 -> '\' 'U' "00010000"}<br>
	 *
	 * @param codePoint int value
	 */
	public void addEscapedCodePoint(int codePoint) {
		ensureTextMode();
		char escapeChar =
			(codePoint < MAX_ASCII) ? 'x' : Character.isBmpCodePoint(codePoint) ? 'u' : 'U';
		int cpDigits = (codePoint < MAX_ASCII) ? 2 : Character.isBmpCodePoint(codePoint) ? 4 : 8;
		String s = Integer.toHexString(codePoint).toUpperCase();
		sb.append("\\").append(escapeChar);
		sb.append(StringUtilities.pad(s, '0', cpDigits));
	}

	/**
	 * Adds the characters found in the supplied {@link ByteBuffer} to the result.
	 * <p>
	 * Any portions of the byte buffer that cause problems for the charset codec will be added
	 * as a {@link #addByteSeq(ByteBuffer, int) byte sequence}.
	 * <p>
	 * Characters that are outside the traditional ASCII range will be rendered as-is or as
	 * escape sequences, depending on the RENDER_ENUM setting.
	 *  
	 * @param bb {@link ByteBuffer} containing bytes of a string
	 * @param cs {@link Charset} that should be used to decode the bytes
	 * @param renderSetting {@link RENDER_ENUM}
	 * @param trimTrailingNulls boolean flag, if true trailing null bytes will not be included
	 * in the rendered output
	 */
	public void decodeBytesUsingCharset(ByteBuffer bb, Charset cs, RENDER_ENUM renderSetting,
			boolean trimTrailingNulls) {
		CharsetDecoder codec = cs.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT);
		CharBuffer cb = CharBuffer.allocate(Math.min(10, bb.remaining()));
		while (bb.hasRemaining()) {
			CoderResult cr = codec.decode(bb, cb, true);
			if (!bb.hasRemaining() && trimTrailingNulls) {
				// if this is the last chunk of text, trim nulls if necessary
				// TODO: this conditional is a bit fragile and could fail to trigger if a long
				// run of trailing nulls was split over multiple charbuffers.  This shouldn't
				// happen because of the allocated size of the charbuffer is tied to the size of the
				// input bytebuffer
				trimTrailingNulls(cb);
			}
			flushStringModeCharBuf(cb, renderSetting);
			if ( cr.isError() ) {
				addByteSeq(bb, cr.length());
			}
			else if (cr.isUnderflow()) {
				// there was a trailing byte sequence that the charset needs more bytes to
				// finish. Since we gave the charset all the bytes, any remaining will have to
				// be rendered as bytes values.
				// This can also trigger for successful end-of-input, remaining == 0
				addByteSeq(bb, bb.remaining());
			}
		}

		CoderResult flushResult = codec.flush(cb);
		if (!flushResult.isUnderflow()) {
			// error, should not happen
		}
		flushStringModeCharBuf(cb, renderSetting);
	}

	private void addString(String str) {
		ensureTextMode();
		sb.append(str);
	}

	private void addCodePointChar(int codePoint) {
		ensureTextMode();
		if (codePoint == quoteChar) {
			sb.append("\\");
		}
		sb.appendCodePoint(codePoint);
	}

	private void addByteSeq(ByteBuffer bytes, int count) {
		for (int i = 0; i < count; i++) {
			ensureByteMode();
			sb.append("%02Xh".formatted(bytes.get()));
		}
	}

	private void trimTrailingNulls(CharBuffer cb) {
		while (cb.position() > 0 && cb.get(cb.position() - 1) == 0) {
			cb.position(cb.position() - 1);
		}
	}

	private void flushStringModeCharBuf(CharBuffer cb, RENDER_ENUM renderSetting) {
		cb.flip();
		renderChars(cb, renderSetting);
		cb.clear();
	}

	private void renderChars(CharSequence stringValue, RENDER_ENUM renderSetting) {
		for (int i = 0, strLength = stringValue.length(); i < strLength;) {
			int codePoint = Character.codePointAt(stringValue, i);

			if (StringUtilities.isDisplayable(codePoint)) {
				addCodePointChar(codePoint);
			}
			else if (codePoint == 0) {
				// TODO: there is an opportunity to make this smarter by not switching from
				// byte mode to string mode to add nulls.
				addString("\\0");
			}
			else if (StringUtilities.isControlCharacterOrBackslash(codePoint)) {
				addString(StringUtilities.convertCodePointToEscapeSequence(codePoint));
			}
			else if (Character.isISOControl(codePoint) || !Character.isDefined(codePoint) ||
				codePoint == StringUtilities.UNICODE_BE_BYTE_ORDER_MARK) {
				addEscapedCodePoint(codePoint);
			}
			else if (renderSetting == RENDER_ENUM.ALL) {
				addCodePointChar(codePoint);
			}
			else {
				addEscapedCodePoint(codePoint);
			}

			i += Character.charCount(codePoint);
		}

	}

	private void ensureTextMode() {
		if (sb.length() == 0) {
			sb.append(quoteChar);
		}
		else if (byteMode) {
			sb.append(',');
			sb.append(quoteChar);
		}
		byteMode = false;
	}

	private void ensureByteMode() {
		if (!byteMode) {
			sb.append(quoteChar);
		}
		if (sb.length() > 0) {
			sb.append(',');
		}
		byteMode = true;
	}

	public String build() {
		// TODO: change the string prefix modifier to align with what decompiler does 
		String s = !sb.isEmpty() ? toString() : "%c%c".formatted(quoteChar, quoteChar); // '' won't make sense
		String prefix = "";
		if (utfCharset && !s.isEmpty() && s.charAt(0) == quoteChar) {
			prefix = switch (charSize) {
				case 1 -> "u8";
				case 2 -> "u";
				case 4 -> "U";
				default -> "";
			};
		}
		return prefix + s;
	}

	/**
	 * Example (quotes are part of result): {@code "Test\tstring",01,02,"Second\npart",00}
	 * <p>
	 * @return Formatted string
	 */
	@Override
	public String toString() {
		String str = sb.toString();
		if (!byteMode) {
			// close the quoted text mode in the local string
			str += quoteChar;
		}
		return str;
	}

}
