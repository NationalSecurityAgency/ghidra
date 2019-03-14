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
package ghidra.app.plugin.languages.sleigh;

import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;

/**
 * A class to traverse SLEIGH constructors in a language
 * 
 * @see SleighLanguages#traverseConstructors(SleighLanguage, ConstructorEntryVisitor)
 */
public class SleighConstructorTraversal implements VisitorResults {
	protected final SleighLanguage lang;

	/**
	 * Prepare to traverse the constructors of a given SLEIGH language
	 * @param lang the language
	 */
	public SleighConstructorTraversal(SleighLanguage lang) {
		this.lang = lang;
	}

	/**
	 * An internal visitor
	 * 
	 * The {@link SleighConstructorTraversal#traverse(ConstructorEntryVisitor)} method iterates
	 * over each subtable, traversing each with this visitor. This visitor wraps the visitor given
	 * by the caller.
	 */
	protected static class SubVisitor implements SubtableEntryVisitor {
		protected final SubtableSymbol subtable;
		protected final ConstructorEntryVisitor cev;

		/**
		 * Prepare to traverse a subtable
		 * @param subtable the subtable
		 * @param cev the wrapped constructor visitor to invoke
		 */
		protected SubVisitor(SubtableSymbol subtable, ConstructorEntryVisitor cev) {
			this.subtable = subtable;
			this.cev = cev;
		}

		@Override
		public int visit(DisjointPattern pattern, Constructor cons) {
			return cev.visit(subtable, pattern, cons);
		}
	}

	/**
	 * Traverse the constructors in the language
	 * @param visitor a callback for each constructor
	 * @return a value from {@link VisitorResults}
	 */
	public int traverse(ConstructorEntryVisitor visitor) {
		for (Symbol sym : lang.getSymbolTable().getSymbolList()) {
			if (sym instanceof SubtableSymbol) {
				SubtableSymbol subtable = (SubtableSymbol) sym;
				SleighSubtableTraversal t = new SleighSubtableTraversal(subtable);
				int result = t.traverse(new SubVisitor(subtable, visitor));
				if (result != FINISHED) {
					assert result != CONTINUE;
					return result;
				}
			}
		}
		return FINISHED;
	}
}
