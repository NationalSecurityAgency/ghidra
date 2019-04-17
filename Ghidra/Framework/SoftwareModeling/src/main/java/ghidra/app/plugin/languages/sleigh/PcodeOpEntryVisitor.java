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
import ghidra.app.plugin.processors.sleigh.template.OpTpl;

/**
 * An interface for visiting Pcode operations in a SLEIGH language
 * 
 * @see SleighLanguages#traverseAllPcodeOps(SleighLanguage, PcodeOpEntryVisitor)
 */
public interface PcodeOpEntryVisitor extends VisitorResults {
	/**
	 * Callback to visit a Pcode operation
	 * @param subtable the table containing the constructor
	 * @param pattern the pattern corresponding to the constructor
	 * @param cons the constructor generating the Pcode operation
	 * @param op the Pcode operation
	 * @return a value from {@link VisitorResults}
	 */
	public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons, OpTpl op);
}
