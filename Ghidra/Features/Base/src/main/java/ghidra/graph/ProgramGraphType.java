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
package ghidra.graph;

import java.util.*;

import org.apache.commons.text.WordUtils;

import ghidra.program.model.symbol.RefType;
import ghidra.service.graph.GraphType;

/**
 * Defines a common set of vertex and edge types {@link GraphType} for program code and data flow
 * graphs. Each specific type of program graph will use a subclass to specifically identify the
 * graph type.
 */

public abstract class ProgramGraphType extends GraphType {
	private static Map<RefType, String> refTypeToEdgeTypeMap = new HashMap<>();
	private static List<String> vertexTypes = new ArrayList<>();
	private static List<String> edgeTypes = new ArrayList<>();
	//@formatter:off
	
	// Vertex Types
	public static final String BODY = vertex("Body");
	public static final String ENTRY = vertex("Entry");
	public static final String EXIT = vertex("Exit");
	public static final String SWITCH = vertex("Switch");
	public static final String EXTERNAL = vertex("External");
	public static final String BAD = vertex("Bad");
	public static final String INSTRUCTION = vertex("Instruction");
	public static final String DATA = vertex("Data");
	public static final String ENTRY_NEXUS = vertex("Entry-Nexus");
	public static final String STACK = vertex("Stack");
	
	// Edge Types - Flow
	public static final String ENTRY_EDGE = edge("Entry");  // This edge if for adding an "Entry Nexus" Vertex
	public static final String FALL_THROUGH = edge(map(RefType.FALL_THROUGH));
	public static final String UNCONDITIONAL_JUMP = edge(map(RefType.UNCONDITIONAL_JUMP));
	public static final String UNCONDITIONAL_CALL = edge(map(RefType.UNCONDITIONAL_CALL));
	public static final String TERMINATOR = edge(map(RefType.TERMINATOR));
	public static final String JUMP_TERMINATOR = edge(map(RefType.JUMP_TERMINATOR));
	public static final String INDIRECTION = edge(map(RefType.INDIRECTION));

	public static final String CONDITIONAL_JUMP = edge(map(RefType.CONDITIONAL_JUMP));
	public static final String CONDITIONAL_CALL = edge(map(RefType.CONDITIONAL_CALL));
	public static final String CONDITIONAL_TERMINATOR = edge(map(RefType.CONDITIONAL_TERMINATOR));
	public static final String CONDITIONAL_CALL_TERMINATOR =edge(map(RefType.CONDITIONAL_CALL_TERMINATOR));
	
	public static final String COMPUTED_JUMP = edge(map(RefType.COMPUTED_JUMP));
	public static final String COMPUTED_CALL = edge(map(RefType.COMPUTED_CALL));
	public static final String COMPUTED_CALL_TERMINATOR = edge(map(RefType.COMPUTED_CALL_TERMINATOR));
	
	public static final String CONDITIONAL_COMPUTED_CALL = edge(map(RefType.CONDITIONAL_COMPUTED_CALL));
	public static final String CONDITIONAL_COMPUTED_JUMP =edge(map(RefType.CONDITIONAL_COMPUTED_JUMP));

	public static final String CALL_OVERRIDE_UNCONDITIONAL = edge(map(RefType.CALL_OVERRIDE_UNCONDITIONAL));
	public static final String JUMP_OVERRIDE_UNCONDITIONAL = edge(map(RefType.CALL_OVERRIDE_UNCONDITIONAL));
	public static final String CALLOTHER_OVERRIDE_CALL = edge(map(RefType.CALL_OVERRIDE_UNCONDITIONAL));
	public static final String CALLOTHER_OVERRIDE_JUMP = edge(map(RefType.CALL_OVERRIDE_UNCONDITIONAL));

	// Edge Types Data Refs
	public static final String READ = edge(map(RefType.READ));
	public static final String WRITE = edge(map(RefType.WRITE));
	public static final String READ_WRITE = edge(map(RefType.READ_WRITE));
	public static final String UNKNOWN_DATA = edge(map(RefType.DATA));
	public static final String EXTERNAL_REF = edge(map(RefType.EXTERNAL_REF));
	
	public static final String READ_INDIRECT = edge(map(RefType.READ_IND));
	public static final String WRITE_INDIRECT = edge(map(RefType.WRITE_IND));
	public static final String READ_WRITE_INDIRECT = edge(map(RefType.READ_WRITE_IND));
	public static final String DATA_INDIRECT = edge(map(RefType.DATA_IND));

	public static final String PARAM = edge(map(RefType.PARAM));
	public static final String THUNK = edge(map(RefType.THUNK));
	
	//@formatter:on

	protected ProgramGraphType(String name, String description) {
		super(name, description, vertexTypes, edgeTypes);
	}

	private static String vertex(String vertexType) {
		vertexTypes.add(vertexType);
		return vertexType;
	}

	private static String edge(String edgeType) {
		edgeTypes.add(edgeType);
		return edgeType;
	}

	private static String map(RefType refType) {
		String edgeTypeName = fixup(refType.getName());
		refTypeToEdgeTypeMap.put(refType, edgeTypeName);
		return edgeTypeName;
	}

	private static String fixup(String name) {
		name = name.replace('_', ' ');
		return WordUtils.capitalizeFully(name);
	}

	public static String getEdgeType(RefType refType) {
		return refTypeToEdgeTypeMap.get(refType);
	}

	@Override
	public String getOptionsName() {
		return "Program Graph Display Options";
	}

}
