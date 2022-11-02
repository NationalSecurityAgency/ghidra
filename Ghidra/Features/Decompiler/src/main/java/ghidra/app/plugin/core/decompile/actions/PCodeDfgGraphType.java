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
package ghidra.app.plugin.core.decompile.actions;

import java.util.ArrayList;
import java.util.List;

import ghidra.service.graph.GraphType;

/**
 * GraphType for a PCode data flow graph
 */
public class PCodeDfgGraphType extends GraphType {
	private static List<String> vertexTypes = new ArrayList<>();
	private static List<String> edgeTypes = new ArrayList<>();

	// Vertex Types
	public static final String DEFAULT_VERTEX = vertex("Default");
	public static final String CONSTANT = vertex("Constant");
	public static final String REGISTER = vertex("Register");
	public static final String UNIQUE = vertex("Unique");
	public static final String PERSISTENT = vertex("Persistent");
	public static final String ADDRESS_TIED = vertex("Address Tied");
	public static final String OP = vertex("Op");

	// Edge Types
	public static final String DEFAULT_EDGE = edge("Default");
	public static final String WITHIN_BLOCK = edge("Within Block");
	public static final String BETWEEN_BLOCKS = edge("Between Blocks");

	public PCodeDfgGraphType() {
		super("AST Graph", "Displays an AST graph for the current function", vertexTypes,
			edgeTypes);
	}

	private static String edge(String edgeType) {
		edgeTypes.add(edgeType);
		return edgeType;
	}

	private static String vertex(String vertexType) {
		vertexTypes.add(vertexType);
		return vertexType;
	}

}
