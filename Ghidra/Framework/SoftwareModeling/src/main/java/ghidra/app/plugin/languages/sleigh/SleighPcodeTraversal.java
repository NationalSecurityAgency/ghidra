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
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;

/**
 * A class to traverse SLEIGH Pcode operations in a language
 */
class SleighPcodeTraversal implements VisitorResults {
	protected final Constructor cons;

	/**
	 * Prepare to traverse the Pcode entries of a given constructor
	 * @param cons
	 */
	public SleighPcodeTraversal(Constructor cons) {
		this.cons = cons;
	}

	/**
	 * Traverse the Pcode operations in the constructor
	 * @param visitor a callback for each Pcode operation
	 * @return a value from {@link VisitorResults}
	 */
	public int traverse(OnlyPcodeOpEntryVisitor visitor) {
		ConstructTpl ctpl = cons.getTempl();
		for (OpTpl op : ctpl.getOpVec()) {
			int result = visitor.visit(op);
			if (result != CONTINUE) {
				return result;
			}
		}
		return FINISHED;
	}

	/**
	 * An interface for visiting Pcode operations in a constructor
	 * 
	 * @see SleighPcodeTraversal#traverse(OnlyPcodeOpEntryVisitor)
	 * NOTE: This is meant for internal use only
	 */
	static interface OnlyPcodeOpEntryVisitor extends VisitorResults {
		public int visit(OpTpl op);
	}
}
