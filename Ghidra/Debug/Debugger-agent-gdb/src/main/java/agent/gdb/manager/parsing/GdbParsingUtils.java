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
package agent.gdb.manager.parsing;

import java.math.BigInteger;
import java.nio.CharBuffer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Some utility methods for working with GDB
 */
public enum GdbParsingUtils {
	;

	public static abstract class AbstractGdbParser {
		protected final CharBuffer buf;

		protected AbstractGdbParser(CharSequence text) {
			this.buf = CharBuffer.wrap(text);
		}

		protected String match(Pattern pat, boolean chompWhitespace) throws GdbParseError {
			return match(pat, chompWhitespace, null);
		}

		protected String match(Pattern pat, boolean chompWhitespace, String group)
				throws GdbParseError {
			if (chompWhitespace) {
				chompWhitespace();
			}
			Matcher mat = pat.matcher(buf);
			if (mat.lookingAt()) {
				String result = group == null ? mat.group() : mat.group(group);
				// TODO: Might just need end?
				int length = mat.end() - mat.start();
				buf.position(buf.position() + length);
				return result;
			}
			throw new GdbParseError("" + pat, buf);
		}

		/**
		 * Peek at the next character
		 * 
		 * @param chompWhitespace true to consume all whitespace at the current position first
		 * @return the next character
		 */
		protected char peek(boolean chompWhitespace) {
			if (chompWhitespace) {
				chompWhitespace();
			}
			if (!buf.hasRemaining()) {
				return '\0';
			}
			return buf.get(buf.position());
		}

		/**
		 * Advance the buffer position past any whitespace
		 */
		protected void chompWhitespace() {
			while (buf.hasRemaining() && Character.isWhitespace(buf.get(buf.position()))) {
				buf.get();
			}
		}

		/**
		 * Check that the parser has reached the end of the line (EOL)
		 * 
		 * @throws GdbParseError if there is text remaining
		 */
		protected void checkEmpty(boolean chompWhitespace) throws GdbParseError {
			if (chompWhitespace) {
				chompWhitespace();
			}
			if (buf.hasRemaining()) {
				throw new GdbParseError("EOL", buf);
			}
		}
	}

	/**
	 * An exception that is thrown when the manager cannot parse a command result, event, or value
	 */
	public static class GdbParseError extends Exception {
		/**
		 * Construct a description of a parse error
		 * 
		 * @param expected the character(s) expected
		 * @param s the tail from the first rejected character
		 */
		public GdbParseError(String expected, CharSequence s) {
			super("Expected [" + expected + "] at tail '" + s + "'");
		}
	}

	/**
	 * Parse a hex string to a long
	 * 
	 * <P>
	 * The string must have the {@code 0x} prefix
	 * 
	 * @param hex the string
	 * @return the parsed long
	 */
	public static long parsePrefixedHex(String hex) {
		if (!hex.startsWith("0x")) {
			throw new NumberFormatException("Hex must start with 0x");
		}
		return Long.parseUnsignedLong(hex.substring(2), 16);
	}

	/**
	 * Parse a hex string to a big integer
	 * 
	 * <P>
	 * The string must have the {@code 0x} prefix
	 * 
	 * @param hex the string
	 * @return the parsed big integer
	 */
	public static BigInteger parsePrefixedHexBig(String hex) {
		if (!hex.startsWith("0x")) {
			throw new NumberFormatException("Hex must start with 0x");
		}
		return new BigInteger(hex.substring(2), 16);
	}

	/**
	 * Parse an octal string to a long
	 * 
	 * <P>
	 * The string must have the {@code 0} prefix
	 * 
	 * @param oct the string
	 * @return the parsed long
	 */
	public static long parsePrefixedOctal(String oct) {
		if (!oct.startsWith("0")) {
			throw new NumberFormatException("Octal must start with 0");
		}
		return Long.parseUnsignedLong(oct, 8);
	}

	/**
	 * Parse an inferior id
	 * 
	 * <P>
	 * The id must have the {@code i} prefix
	 * 
	 * @param id the string
	 * @return the parsed integer
	 */
	public static int parseInferiorId(String id) {
		if (!id.startsWith("i")) {
			throw new IllegalArgumentException(
				"Map id does not specify an inferior. Must start with 'i'");
		}
		return Integer.parseInt(id.substring(1));
	}
}
