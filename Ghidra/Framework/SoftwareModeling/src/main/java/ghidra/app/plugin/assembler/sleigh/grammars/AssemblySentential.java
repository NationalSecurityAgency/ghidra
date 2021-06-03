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

import org.apache.commons.collections4.list.AbstractListDecorator;

import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;

/**
 * A "string" of symbols
 * 
 * To avoid overloading the word "String", we call this a "sentential". Technically, to be a
 * "sentential" in the classic sense, it must be a possible element in the derivation of a sentence
 * in the grammar starting with the start symbol. We ignore that if only for the sake of naming.
 * 
 * @param <NT> the type of non-terminals
 */
public class AssemblySentential<NT extends AssemblyNonTerminal> extends
		AbstractListDecorator<AssemblySymbol> implements Comparable<AssemblySentential<NT>> {
	private List<AssemblySymbol> symbols;
	private boolean finished = false;
	public static final AssemblyStringTerminal WHITE_SPACE = new WhiteSpace();

	/**
	 * Construct a string from the given list of symbols
	 * @param symbols
	 */
	public AssemblySentential(List<? extends AssemblySymbol> symbols) {
		this.symbols = new ArrayList<>(symbols);
	}

	@Override
	protected List<AssemblySymbol> decorated() {
		return symbols;
	}

	/**
	 * Construct a blank string
	 * 
	 * This is suitable as a blank start, to add new symbols, or to use directly as the RHS,
	 * effectively creating an "epsilon" production.
	 */
	public AssemblySentential() {
		this.symbols = new ArrayList<>();
	}

	/**
	 * Construct a string from any number of symbols
	 * @param syms
	 */
	public AssemblySentential(AssemblySymbol... syms) {
		this.symbols = Arrays.asList(syms);
	}

	@Override
	public String toString() {
		if (symbols.size() == 0) {
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
				Map<String, Long> labels) {
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
		public Collection<String> getSuggestions(String got, Map<String, Long> labels) {
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
	 * "Expected" tokens given by a parse machine when this is the last token it has consumed are
	 * not valid suggestions. The machine should instead suggest a whitespace character.
	 */
	public static class TruncatedWhiteSpaceParseToken extends WhiteSpaceParseToken {
		public TruncatedWhiteSpaceParseToken(AssemblyGrammar grammar, AssemblyTerminal term) {
			super(grammar, term, "");
		}
	}

	/**
	 * Add "optional" whitespace, if not already preceded by whitespace
	 * @return true if whitespace was added
	 */
	public boolean addWS() {
		WhiteSpace last = lastWhiteSpace();
		if (last != null) {
			return false;
		}
		return add(WHITE_SPACE);
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
	 * Trim leading and trailing whitespace, and make the string immutable
	 */
	public void finish() {
		if (finished) {
			return;
		}
		symbols = Collections.unmodifiableList(symbols);
		finished = true;
	}

	@Override
	public AssemblySentential<NT> subList(int fromIndex, int toIndex) {
		return new AssemblySentential<>(symbols.subList(fromIndex, toIndex));
	}
}
