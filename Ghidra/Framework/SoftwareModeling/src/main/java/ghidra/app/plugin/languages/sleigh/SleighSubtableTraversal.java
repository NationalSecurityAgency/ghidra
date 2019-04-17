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

import java.util.Iterator;

import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.DecisionNode;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * A class to traverse SLEIGH constructors in a single table
 * 
 * @see SleighLanguages#traverseConstructors(SubtableSymbol, SubtableEntryVisitor)
 */
class SleighSubtableTraversal implements VisitorResults {
	protected final SubtableSymbol sub;

	/**
	 * Prepare to traverse the constructors of a given table
	 * @param sub the table
	 */
	public SleighSubtableTraversal(SubtableSymbol sub) {
		this.sub = sub;
	}

	/**
	 * Traverse the constructors in the table
	 * @param visitor a callback for each constructor
	 * @return a value from {@link VisitorResults}
	 */
	public int traverse(SubtableEntryVisitor visitor) {
		int result = traverse(sub.getDecisionNode(), visitor);
		if (result == CONTINUE) {
			return FINISHED;
		}
		return result;
	}

	/**
	 * A recursive method to descend down each branch of the decision tree for a table
	 * @param node the current node
	 * @param visitor the visitor to call back
	 * @return a value from {@link VisitorResults}
	 */
	protected int traverse(DecisionNode node, SubtableEntryVisitor visitor) {
		Iterator<DisjointPattern> pit = node.getPatterns().iterator();
		Iterator<Constructor> cit = node.getConstructors().iterator();
		while (pit.hasNext()) {
			int result = visitor.visit(pit.next(), cit.next());
			if (result != CONTINUE) {
				return result;
			}
		}
		for (DecisionNode child : node.getChildren()) {
			int result = traverse(child, visitor);
			if (result != CONTINUE) {
				return result;
			}
		}
		return CONTINUE;
	}
}
