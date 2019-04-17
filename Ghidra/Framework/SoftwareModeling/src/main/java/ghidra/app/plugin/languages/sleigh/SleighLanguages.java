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

import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.app.plugin.languages.sleigh.SleighPcodeTraversal.OnlyPcodeOpEntryVisitor;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;

/**
 * A collection of utility functions for traversing constructors and Pcode operations of SLEIGH
 * languages
 */
public class SleighLanguages {
	/**
	 * Traverse the constructors of a given SLEIGH language
	 * @param lang the language
	 * @param visitor a callback for each constructor visited
	 * @return a value from {@link VisitorResults}
	 */
	public static int traverseConstructors(SleighLanguage lang, ConstructorEntryVisitor visitor) {
		return new SleighConstructorTraversal(lang).traverse(visitor);
	}

	/**
	 * Traverse the constructors of a given table
	 * @param subtable the table
	 * @param visitor a callback for each constructor visited
	 * @return a value from {@link VisitorResults}
	 */
	public static int traverseConstructors(SubtableSymbol subtable, SubtableEntryVisitor visitor) {
		return new SleighSubtableTraversal(subtable).traverse(visitor);
	}

	/**
	 * Traverse the Pcode operations of a given SLEIGH language
	 * 
	 * During traversal, if a "NOP" constructor, i.e., one having no Pcode operations, is
	 * encountered, the callback is still invoked at least once, with a null Pcode operation. This
	 * is so NOP constructors are not overlooked by this traversal.
	 * @param lang the language
	 * @param visitor a callback for each Pcode operation visited
	 * @return a value from {@link VisitorResults}
	 */
	public static int traverseAllPcodeOps(SleighLanguage lang, PcodeOpEntryVisitor visitor) {
		return traverseConstructors(lang, new ConsVisitForPcode(visitor));
	}

	/**
	 * An internal visitor
	 * 
	 * The {@link SleighLanguages#traverseAllPcodeOps(SleighLanguage, PcodeOpEntryVisitor)} method
	 * uses this visitor to traverse every constructor a given language. For each constructor, it
	 * then applies another (anonymous) visitor to traverse each Pcode operation in the visited
	 * constructor. That anonymous visitor wraps the visitor given by the caller.
	 */
	protected static class ConsVisitForPcode implements ConstructorEntryVisitor {
		protected final PcodeOpEntryVisitor visitor;

		/**
		 * Prepare to traverse a constructor
		 * @param visitor the wrapped Pcode operation visitor to invoke
		 */
		public ConsVisitForPcode(PcodeOpEntryVisitor visitor) {
			this.visitor = visitor;
		}

		@Override
		public int visit(final SubtableSymbol subtable, final DisjointPattern pattern,
				final Constructor cons) {
			final AtomicBoolean atLeastOne = new AtomicBoolean(false);
			int result = new SleighPcodeTraversal(cons).traverse(new OnlyPcodeOpEntryVisitor() {
				@Override
				public int visit(OpTpl op) {
					atLeastOne.set(true);
					return visitor.visit(subtable, pattern, cons, op);
				}
			});
			if (!atLeastOne.get()) {
				visitor.visit(subtable, pattern, cons, null);
			}
			if (result != FINISHED) {
				assert result != CONTINUE;
				return TERMINATE;
			}
			return CONTINUE;
		}
	}
}
