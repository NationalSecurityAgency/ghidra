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
import java.util.stream.Collectors;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;
import ghidra.program.model.address.AddressSpace;

/**
 * A terminal that accepts any numeric value or program symbol (label, equate)
 * 
 * <p>
 * The literal may take any form accepted by UNIX strtol() with base=0. By default, the literal is
 * interpreted in base 10, but it may be prefixed such that it's interpreted in an alternative base.
 * With the prefix '0x', it is interpreted in hexadecimal. With the prefix '0', it is interpreted in
 * octal.
 * 
 * <p>
 * It may also take the value of a label. If this operand is an address operand, the acceptable
 * labels are restricted to those in the expected address space.
 */
public class AssemblyNumericTerminal extends AssemblyTerminal {
	public static final String PREFIX_HEX = "0x";
	public static final String PREFIX_OCT = "0";

	/** Some suggestions, other than labels, to provide */
	protected static final Collection<String> SUGGESTIONS =
		List.of("0", "1", "0x0", "+0x0", "-0x0", "01");
	/** The maximum number of labels to suggest */
	protected static final int MAX_LABEL_SUGGESTIONS = 10;

	protected final int bitsize;
	protected final AddressSpace space;

	/**
	 * Construct a terminal with the given name, accepting any numeric value or program label
	 * 
	 * @param name the name
	 * @param bitsize the maximum size of the value in bits
	 * @param space the address space if this terminal represents an address operand
	 */
	public AssemblyNumericTerminal(String name, int bitsize, AddressSpace space) {
		super(name);
		this.bitsize = bitsize;
		this.space = space;
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
	 * <p>
	 * Please use {@link #match(String, int, AssemblyGrammar, AssemblyNumericSymbols)}
	 * 
	 * @param buffer the input buffer
	 * @return the parsed token
	 */
	public AssemblyParseNumericToken match(String buffer) {
		Collection<AssemblyParseNumericToken> col =
			match(buffer, 0, null, AssemblyNumericSymbols.EMPTY);
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
			AssemblyGrammar grammar, AssemblyNumericSymbols symbols) {
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
			return match(pos, buffer, grammar, symbols);
		}
	}

	/**
	 * Try to match a sign-less numeric literal, or a program label
	 * 
	 * @param s the buffer cursor where the literal or label is expected
	 * @param buffer the input buffer
	 * @param grammar the grammar containing this terminal
	 * @param symbols the program symbols
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> match(int s, String buffer,
			AssemblyGrammar grammar, AssemblyNumericSymbols symbols) {
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
		return symbols.choose(lab, space)
				.stream()
				.map(val -> new AssemblyParseNumericToken(grammar, this, lab, val))
				.collect(Collectors.toList());
	}

	/**
	 * Try to match a numeric literal, after the optional sign, encoded in hex, decimal, or octal
	 * 
	 * @param s buffer cursor where the literal is expected
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the optional {@code -} is present
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
	 * 
	 * @param str the string value of the token taken verbatim from the buffer
	 * @param num portion of the token following the optional sign and prefix
	 * @param radix the radix of {@code num}
	 * @param neg true if the optional {@code -} is present
	 * @param grammar the grammar containing this terminal
	 * @return the parsed token, or null
	 */
	protected Collection<AssemblyParseNumericToken> makeToken(String str, String num, int radix,
			boolean neg, AssemblyGrammar grammar) {
		if (num.length() == 0) {
			return Collections.emptySet();
		}
		try {
			long val = Long.parseUnsignedLong(num, radix);
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
	 * 
	 * @param s the buffer cursor where the hex portion starts
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the optional {@code -} is present
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
	 * 
	 * @param s the buffer cursor where the hex portion starts
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the optional {@code -} is present
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
	 * 
	 * @param s the buffer cursor where the hex portion starts
	 * @param buffer the input buffer
	 * @param pos the start offset of the token parsed so far
	 * @param neg true if the optional {@code -} is present
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
	public Collection<String> getSuggestions(String got, AssemblyNumericSymbols symbols) {
		Set<String> s = new TreeSet<>(SUGGESTIONS);
		s.addAll(symbols.getSuggestions(got, space, MAX_LABEL_SUGGESTIONS));
		return s;
	}

	public int getBitSize() {
		return bitsize;
	}

	public AddressSpace getSpace() {
		return space;
	}
}
