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
package ghidra.app.plugin.assembler.sleigh.grammars;

import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;

/**
 * A "string" of symbols
 * 
 * <p>
 * To avoid overloading the word "string", we call this a "sentential". Technically, to be a
 * "sentential" in the classic sense, it must be a possible element in the derivation of a sentence
 * in the grammar starting with the start symbol. We ignore that if only for the sake of naming.
 * 
 * @param <NT> the type of non-terminals
 */
public class AssemblySentential<NT extends AssemblyNonTerminal>
		implements Comparable<AssemblySentential<NT>>, Iterable<AssemblySymbol> {
	private List<AssemblySymbol> symbols;
	private final List<AssemblySymbol> unmodifiableSymbols;
	private boolean finished = false;
	public static final AssemblyStringTerminal WHITE_SPACE = new WhiteSpace();
	private static final Pattern PAT_COMMA_WS = Pattern.compile(",\\s+");

	/**
	 * Construct a string from the given list of symbols
	 * 
	 * @param symbols
	 */
	public AssemblySentential(List<? extends AssemblySymbol> symbols) {
		this.symbols = new ArrayList<>(symbols);
		this.unmodifiableSymbols = Collections.unmodifiableList(symbols);
	}

	/**
	 * Construct a blank string
	 * 
	 * This is suitable as a blank start, to add new symbols, or to use directly as the RHS,
	 * effectively creating an "epsilon" production.
	 */
	public AssemblySentential() {
		this.symbols = new ArrayList<>();
		this.unmodifiableSymbols = Collections.unmodifiableList(symbols);
	}

	/**
	 * Construct a string from any number of symbols
	 * 
	 * @param syms
	 */
	public AssemblySentential(AssemblySymbol... syms) {
		this.symbols = Arrays.asList(syms);
		this.unmodifiableSymbols = Collections.unmodifiableList(symbols);
	}

	@Override
	public String toString() {
		if (symbols.isEmpty()) {
			return "e";
		}
		Iterator<? extends AssemblySymbol> symIt = symbols.iterator();
		StringBuilder sb = new StringBuilder();
		sb.append(symIt.next());
		while (symIt.hasNext()) {
			sb.append(" ");
			sb.append(symIt.next());
		}
		return sb.toString();
	}

	@Override
	public int compareTo(AssemblySentential<NT> that) {
		int result;
		int min = Math.min(this.symbols.size(), that.symbols.size());
		for (int i = 0; i < min; i++) {
			AssemblySymbol a = this.symbols.get(i);
			AssemblySymbol b = that.symbols.get(i);
			result = a.compareTo(b);
			if (result != 0) {
				return result;
			}
		}
		if (that.symbols.size() > min) {
			return -1;
		}
		if (this.symbols.size() > min) {
			return 1;
		}
		return 0;
	}

	@Override
	public int hashCode() {
		int result = 0;
		for (AssemblySymbol sym : symbols) {
			result *= 31;
			result += sym.hashCode();
		}
		return result;
	}

	/**
	 * A "whitespace" terminal
	 * 
	 * <p>
	 * This terminal represents "optional" whitespace. "Optional" because in certain circumstances,
	 * whitespace is not actually required, i.e., before or after a special character.
	 */
	private static class WhiteSpace extends AssemblyStringTerminal {
		private WhiteSpace() {
			super(" ");
		}

		@Override
		public String toString() {
			return "_";
		}

		@Override
		public Collection<AssemblyParseToken> match(String buffer, int pos, AssemblyGrammar grammar,
				AssemblyNumericSymbols symbols) {
			if (buffer.length() == 0) {
				return Collections.singleton(new WhiteSpaceParseToken(grammar, this, ""));
			}
			int b = pos;
			while (b < buffer.length() && Character.isWhitespace(buffer.charAt(b))) {
				b++;
			}
			if (b == pos) {
				if (pos == buffer.length()) {
					if (Character.isLetterOrDigit(buffer.charAt(b - 1))) {
						return Collections.singleton(
							new TruncatedWhiteSpaceParseToken(grammar, this));
					}
					return Collections.singleton(new WhiteSpaceParseToken(grammar, this, ""));
				}
				if (Character.isLetterOrDigit(buffer.charAt(b)) &&
					(b == 0 || Character.isLetterOrDigit(buffer.charAt(b - 1)))) {
					return Collections.emptySet();
				}
			}
			return Collections.singleton(
				new WhiteSpaceParseToken(grammar, this, buffer.substring(pos, b)));
		}

		@Override
		public Collection<String> getSuggestions(String got, AssemblyNumericSymbols symbols) {
			return Collections.singleton(" ");
		}
	}

	/**
	 * The token consumed by a whitespace terminal
	 */
	public static class WhiteSpaceParseToken extends AssemblyParseToken {
		public WhiteSpaceParseToken(AssemblyGrammar grammar, AssemblyTerminal term, String str) {
			super(grammar, term, str);
		}
	}

	/**
	 * The token consumed by a whitespace terminal when it anticipates the end of input
	 * 
	 * <p>
	 * "Expected" tokens given by a parse machine when this is the last token it has consumed are
	 * not valid suggestions. The machine should instead suggest a whitespace character.
	 */
	public static class TruncatedWhiteSpaceParseToken extends WhiteSpaceParseToken {
		public TruncatedWhiteSpaceParseToken(AssemblyGrammar grammar, AssemblyTerminal term) {
			super(grammar, term, "");
		}
	}

	/**
	 * Add a symbol to the right of this sentential
	 * 
	 * @param symbol the symbol to add
	 * @return true
	 */
	public boolean addSymbol(AssemblySymbol symbol) {
		return symbols.add(symbol);
	}

	/**
	 * Add optional whitespace, if not already preceded by whitespace
	 * 
	 * @return true if whitespace was added
	 */
	public boolean addWS() {
		WhiteSpace last = lastWhiteSpace();
		if (last != null) {
			return false;
		}
		return addSymbol(WHITE_SPACE);
	}

	/**
	 * Add a comma followed by optional whitespace.
	 */
	public void addCommaWS() {
		addSymbol(new AssemblyStringTerminal(","));
		addWS();
	}

	/**
	 * Add a syntactic terminal element, but with consideration for optional whitespace surrounding
	 * special characters
	 * 
	 * @param str the expected terminal
	 */
	public void addSeparatorPart(String str) {
		String tstr = str.trim();
		if (tstr.equals("")) {
			addWS();
			return;
		}
		char first = tstr.charAt(0);
		if (!str.startsWith(tstr)) {
			addWS();
		}
		if (!Character.isLetterOrDigit(first)) {
			addWS();
		}
		addSymbol(new AssemblyStringTerminal(tstr));
		char last = tstr.charAt(tstr.length() - 1);
		if (!str.endsWith(tstr)) {
			addWS();
		}
		if (!Character.isLetterOrDigit(last)) {
			addWS();
		}
	}

	/**
	 * Get the symbols in this sentential
	 * 
	 * @return the symbols;
	 */
	public List<AssemblySymbol> getSymbols() {
		return unmodifiableSymbols;
	}

	public AssemblySymbol getSymbol(int pos) {
		return symbols.get(pos);
	}

	/**
	 * Split the given string into pieces matched by the pattern, and the pieces between
	 * 
	 * <p>
	 * This invokes the given callbacks as the string is processed from left to right.
	 * 
	 * @param str the string to split
	 * @param pat the pattern to match
	 * @param matched the callback for matched portions
	 * @param unmatched the callback for unmatched portions
	 */
	private static void forMatchUnmatch(String str, Pattern pat, Consumer<String> matched,
			Consumer<String> unmatched) {
		int startU = 0;
		Matcher mat = pat.matcher(str);
		while (mat.find()) {
			if (startU < mat.start()) {
				unmatched.accept(str.substring(startU, mat.start()));
			}
			matched.accept(mat.group());
			startU = mat.end();
		}
		if (startU < str.length()) {
			unmatched.accept(str.substring(startU));
		}
	}

	/**
	 * Add a syntactic terminal element, but considering that commas contained within may be
	 * followed by optional whitespace
	 * 
	 * @param str the expected terminal
	 */
	public void addSeparators(String str) {
		// NB. When displaying print pieces, the disassembler replaces all ",\\s+" with ","
		forMatchUnmatch(str, PAT_COMMA_WS, matched -> addCommaWS(), this::addSeparatorPart);
	}

	// If the right-most symbol is whitespace, return it
	private WhiteSpace lastWhiteSpace() {
		if (symbols.size() == 0) {
			return null;
		}
		AssemblySymbol last = symbols.get(symbols.size() - 1);
		if (last instanceof WhiteSpace) {
			return (WhiteSpace) last;
		}
		return null;
	}

	/**
	 * Trim leading and trailing whitespace, and make the sentential immutable
	 */
	public void finish() {
		if (finished) {
			return;
		}
		symbols = unmodifiableSymbols;
		finished = true;
	}

	@Override
	public Iterator<AssemblySymbol> iterator() {
		return unmodifiableSymbols.iterator();
	}

	public AssemblySentential<NT> sub(int fromIndex, int toIndex) {
		return new AssemblySentential<>(symbols.subList(fromIndex, toIndex));
	}

	/**
	 * Get the number of symbols, including whitespace, in this sentential
	 * 
	 * @return the number of symbols
	 */
	public int size() {
		return symbols.size();
	}
}
