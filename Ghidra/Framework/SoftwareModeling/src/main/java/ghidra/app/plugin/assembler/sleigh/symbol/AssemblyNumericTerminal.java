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
package ghidra.app.plugin.assembler.sleigh.symbol;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;

/**
 * A terminal that accepts any numeric value or program label
 * 
 * The literal may take any form accepted by UNIX strtol() with base=0. By default, the literal is
 * interpreted in base 10, but it may be prefixed such that it's interpreted in an alternative
 * base. With the prefix '0x', it is interpreted in hexadecimal. With the prefix '0', it is
 * interpreted in octal.
 */
public class AssemblyNumericTerminal extends AssemblyTerminal {
	public static final String PREFIX_HEX = "0x";
	public static final String PREFIX_OCT = "0";

	/** Some suggestions, other than labels, to provide */
	protected static final Collection<String> suggestions = Arrays.asList(new String[] { //
		"0", "1", "0x0", "+0x0", "-0x0", "01" //
	});
	/** The maximum number of labels to suggest */
	protected static final int MAX_LABEL_SUGGESTIONS = 10;

	protected final int bitsize;

	// TODO: Not all numeric literals can be substituted for a label
	/**
	 * Construct a terminal with the given name, accepting any numeric value or program label
	 * @param name the name
	 */
	public AssemblyNumericTerminal(String name, int bitsize) {
		super(name);
		this.bitsize = bitsize;
	}

	@Override
	public String toString() {
		if (bitsize == 0) {
			return "[num:" + name + "]";
		}
		return "[num" + bitsize + ":" + name + "]";
	}

	/**
	 * This is only a convenience for testing
	 * 
	 * Please use {@link #match(String, int, AssemblyGrammar, Map) match(String, int, AssemblyGrammar, Map&lt;String, Long&gt;)}.
	 * @param buffer the input buffer
	 * @return the parsed token
	 */
	public AssemblyParseNumericToken match(String buffer) {
		Collection<AssemblyParseNumericToken> col =
			match(buffer, 0, null, AssemblyParser.EMPTY_LABELS);
		if (col.isEmpty()) {
			return null;
		}
		else if (col.size() == 1) {
			return col.iterator().next();
		}
		else {
			throw new AssertionError("Multiple results for a numeric terminal?: " + col);
		}
	}

	@Override
	public Collection<AssemblyParseNumericToken> match(String buffer, int pos,
			AssemblyGrammar grammar, Map<String, Long> labels) {
		if (pos >= buffer.length()) {
			return Collections.emptySet();
		}
		if (buffer.charAt(pos) == '+') {
			return matchLiteral(pos + 1, buffer, pos, false, grammar);
		}
		else if (buffer.charAt(pos) == '-') {
			return matchLiteral(pos + 1, buffer, pos, true, grammar);
		}
		else {
			return match(pos, buffer, grammar, labels);
		}
	}

	/**
	 * Try to match a sign-less numeric literal, or a program label
	 * @param s the buffer cursor where the literal or label is expected
	 * @param buffer the input buffer
	 * @param grammar the grammar containing this terminal
	 * @param labels the program labels, mapped to their values
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> match(int s, String buffer,
			AssemblyGrammar grammar, Map<String, Long> labels) {
		if (s >= buffer.length()) {
			return Collections.emptySet();
		}
		// Try a literal number first
		if (Character.isDigit(buffer.charAt(s))) {
			return matchLiteral(s, buffer, s, false, grammar);
		}
		// Now, try a label
		int b = s;
		while (b < buffer.length()) {
			char c = buffer.charAt(b);
			if (Character.isJavaIdentifierPart(c)) {
				b++;
				continue;
			}
			break;
		}
		String lab = buffer.substring(s, b);
		Long val = labels.get(lab);
		if (val == null) {
			return Collections.emptySet();
		}
		return Collections.singleton(new AssemblyParseNumericToken(grammar, this, lab, val));
	}

	/**
	 * Try to match a numeric literal, after the optional sign, encoded in hex, decimal, or octal
	 * @param s buffer cursor where the literal is expected
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the the optional {@code -} is present
	 * @param grammar the grammar containing this terminal
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> matchLiteral(int s, String buffer, int pos,
			boolean neg, AssemblyGrammar grammar) {
		if (buffer.regionMatches(s, PREFIX_HEX, 0, PREFIX_HEX.length())) {
			return matchHex(s + PREFIX_HEX.length(), buffer, pos, neg, grammar);
		}
		else if (buffer.regionMatches(s, PREFIX_OCT, 0, PREFIX_OCT.length())) {
			return matchOct(s + PREFIX_OCT.length(), buffer, pos, neg, grammar);
		}
		else {
			return matchDec(s, buffer, pos, neg, grammar);
		}
	}

	/**
	 * Construct a numeric token
	 * @param str the string value of the token taken verbatim from the buffer
	 * @param num portion of the token following the optional sign and prefix
	 * @param radix the radix of {@code num}
	 * @param neg true if the the optional {@code -} is present
	 * @param grammar the grammar containing this terminal
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> makeToken(String str, String num, int radix,
			boolean neg, AssemblyGrammar grammar) {
		if (num.length() == 0) {
			return Collections.emptySet();
		}
		try {
			long val = Long.parseLong(num, radix);
			if (neg) {
				val = -val;
			}
			// TODO: I'd really like to know whether or not the printpiece can take a signed value.
			if (bitsize != 0 && bitsize != 64) {
				if (val < (-1L) << (bitsize - 1)) {
					return Collections.emptySet();
				}
				if (val >= 1L << bitsize) {
					return Collections.emptySet();
				}
			}
			return Collections.singleton(new AssemblyParseNumericToken(grammar, this, str, val));
		}
		catch (NumberFormatException e) {
			return Collections.emptySet();
		}
	}

	/**
	 * Try to match a hexadecimal literal, following the optional sign and prefix
	 * @param s the buffer cursor where the hex portion starts
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the the optional {@code -} is present
	 * @param grammar the grammar containing this terminal
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> matchHex(int s, String buffer, int pos,
			boolean neg, AssemblyGrammar grammar) {
		int b = s;
		while (b < buffer.length()) {
			char c = buffer.charAt(b);
			if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f')) {
				b++;
				continue;
			}
			break;
		}
		return makeToken(buffer.substring(pos, b), buffer.substring(s, b), 16, neg, grammar);
	}

	/**
	 * Try to match a decimal literal, following the optional sign and optional prefix
	 * @param s the buffer cursor where the hex portion starts
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the the optional {@code -} is present
	 * @param grammar the grammar containing this terminal
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> matchDec(int s, String buffer, int pos,
			boolean neg, AssemblyGrammar grammar) {
		int b = s;
		while (b < buffer.length()) {
			char c = buffer.charAt(b);
			if ('0' <= c && c <= '9') {
				b++;
				continue;
			}
			break;
		}
		return makeToken(buffer.substring(pos, b), buffer.substring(s, b), 10, neg, grammar);
	}

	/**
	 * Try to match an octal literal, following the optional sign and prefix
	 * @param s the buffer cursor where the hex portion starts
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the the optional {@code -} is present
	 * @param grammar the grammar containing this terminal
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> matchOct(int s, String buffer, int pos,
			boolean neg, AssemblyGrammar grammar) {
		int b = s;
		while (b < buffer.length()) {
			char c = buffer.charAt(b);
			if ('0' <= c && c <= '7') {
				b++;
				continue;
			}
			break;
		}
		if (b == s) {
			// Then the entire token is just 0
			return makeToken(buffer.substring(pos, b), "0", 8, neg, grammar);
		}
		return makeToken(buffer.substring(pos, b), buffer.substring(s, b), 8, neg, grammar);
	}

	@Override
	public Collection<String> getSuggestions(String got, Map<String, Long> labels) {
		Set<String> s = new TreeSet<>(suggestions);
		int labelcount = 0;
		for (String label : labels.keySet()) {
			if (labelcount >= MAX_LABEL_SUGGESTIONS) {
				break;
			}
			if (label.startsWith(got)) {
				s.add(label);
				labelcount++;
			}
		}
		return s;
	}

	public int getBitSize() {
		return bitsize;
	}
}
