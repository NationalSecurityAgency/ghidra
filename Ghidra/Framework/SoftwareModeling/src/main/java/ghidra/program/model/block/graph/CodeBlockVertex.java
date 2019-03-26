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
package ghidra.program.model.block.graph;

import ghidra.program.model.block.CodeBlock;

/**
 * A class for representing a code block within a graph.
 */
public class CodeBlockVertex implements Comparable<CodeBlockVertex> {
	private final CodeBlock codeBlock;
	private final String name;

	/**
	 * Constructor.
	 * 
	 * @param codeBlock the code block for this vertex
	 */
	public CodeBlockVertex(CodeBlock codeBlock) {
		this.codeBlock = codeBlock;
		this.name = codeBlock.getName();
	}

	/**
	 * A constructor that allows for the creation of dummy nodes.  This is useful in graphs 
	 * where multiple entry or exit points need to be parented by a single vertex.
	 * 
	 * @param name the name of this vertex
	 */
	public CodeBlockVertex(String name) {
		this.codeBlock = null;
		this.name = name;
	}

	public CodeBlock getCodeBlock() {
		return codeBlock;
	}

	public String getName() {
		return name;
	}

	/**
	 * Returns true if this vertex is not backed by a code block.
	 * @return true if this vertex is not backed by a code block.
	 */
	public boolean isDummy() {
		return codeBlock == null;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public int compareTo(CodeBlockVertex o) {
		if (codeBlock == null) {
			return 1;
		}
		if (o.codeBlock == null) {
			return -1;
		}
		return codeBlock.getMinAddress().compareTo(o.codeBlock.getMinAddress());
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof CodeBlockVertex)) {
			return false;
		}
		CodeBlockVertex o = (CodeBlockVertex) obj;
		if (codeBlock == null && o.codeBlock == null) {
			return true;
		}
		if (codeBlock == null || o.codeBlock == null) {
			return false;
		}

		// Assumption: we will not have two code blocks with the same min address.  (It is
		// possible that this could not be the case in a custom, user-defined block model.)
		return codeBlock.getMinAddress().equals(o.codeBlock.getMinAddress());
	}

	@Override
	public int hashCode() {
		if (codeBlock == null) {
			return 0;
		}
		return codeBlock.getMinAddress().hashCode();
	}
}
