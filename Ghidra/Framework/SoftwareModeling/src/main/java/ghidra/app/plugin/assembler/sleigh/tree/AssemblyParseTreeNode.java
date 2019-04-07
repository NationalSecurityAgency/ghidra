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
package ghidra.app.plugin.assembler.sleigh.tree;

import java.io.PrintStream;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;

/**
 * A node in a parse tree
 */
public abstract class AssemblyParseTreeNode {
	protected AssemblyParseBranch parent = null;
	protected final AssemblyGrammar grammar;

	/**
	 * Construct a node for a tree parsed by the given grammar
	 * @param grammar the grammar
	 */
	public AssemblyParseTreeNode(AssemblyGrammar grammar) {
		this.grammar = grammar;
	}

	/**
	 * Get the symbol for which this node is substituted
	 * 
	 * For a branch, this is the LHS of the corresponding production. For a token, this is the
	 * terminal whose tokenizer matched it.
	 * @return the symbol
	 */
	public abstract AssemblySymbol getSym();

	/**
	 * Get the branch which contains this node
	 * @return
	 */
	public AssemblyParseBranch getParent() {
		return parent;
	}

	/**
	 * Set the branch which contains this node
	 * @param parent
	 */
	protected void setParent(AssemblyParseBranch parent) {
		// NOTE: Cannot assert, since the LR parser may backtrack and reassign.
		this.parent = parent;
	}

	/**
	 * For debugging: Display this parse tree via the given stream
	 * @param out the stream
	 */
	public void print(PrintStream out) {
		print(out, "");
	}

	/**
	 * For debugging: Display the tree with the given indent
	 * @param out the stream
	 * @param indent the indent
	 */
	protected abstract void print(PrintStream out, String indent);

	/**
	 * Check if this node yields a subconstructor resolution 
	 * @return true if this node yields a subconstructor resolution
	 */
	public boolean isConstructor() {
		return false;
	}

	/**
	 * Check if this node yields a numeric value
	 * @return true if this node yields a numeric value
	 */
	public boolean isNumeric() {
		return false;
	}

	/**
	 * Get the grammar used to parse the tree
	 * @return the grammar
	 */
	public AssemblyGrammar getGrammar() {
		return grammar;
	}

	/**
	 * Generate the string that this node parsed
	 * @return the string
	 */
	public abstract String generateString();
}
