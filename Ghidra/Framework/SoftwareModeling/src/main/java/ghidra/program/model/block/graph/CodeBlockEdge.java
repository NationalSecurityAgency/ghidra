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

import ghidra.graph.DefaultGEdge;

/**
 * A simple edge type for representing a link between two 
 * {@link CodeBlockVertex CodeBlock vertices}.
 */
public class CodeBlockEdge extends DefaultGEdge<CodeBlockVertex> {

	/**
	 * Constructor.
	 * 
	 * @param start the start vertex
	 * @param end the end vertex
	 */
	public CodeBlockEdge(CodeBlockVertex start, CodeBlockVertex end) {
		super(start, end);
	}
}
