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
package ghidra.bsfv;

import java.util.ArrayList;
import java.util.List;

import ghidra.service.graph.GraphType;

/**
 * This class is the {@link GraphType} for BSim Feature Graphs.
 */
public class BSimFeatureGraphType extends GraphType {
	private static List<String> vertexTypes = new ArrayList<>();
	private static List<String> edgeTypes = new ArrayList<>();

	//dataflow vertex types
	public static final String DEFAULT_VERTEX = "Default";
	public static final String CONSTANT_VERTEX = "Constant";
	public static final String VARNODE_ADDRESS = "Address Varnode";
	public static final String BASE_VARNODE_VERTEX = "Base Varnode";
	public static final String SECONDARY_BASE_VARNODE_VERTEX = "Secondary Base Varnode";
	public static final String FUNCTION_INPUT = "Function Input";
	public static final String CONSTANT_FUNCTION_INPUT = "Constant Function Input";
	public static final String PCODE_OP_VERTEX = "Pcode Op";
	public static final String VOID_BASE = "void";
	public static final String COLLAPSED_VARNODE = "Collapsed Varnode";
	public static final String COLLAPSED_OP = "Collapsed Op";

	//dataflow vertex attributes
	public static final String OP_ADDRESS = "Address";
	public static final String PCODE_OUTPUT = "Pcode Output";
	public static final String SIZE = "Size";

	//dataflow edge types
	public static final String DATAFLOW_IN = "Input";
	public static final String DATAFLOW_OUT = "Output";
	public static final String COLLAPSED_IN = "Collapsed Input";
	public static final String COLLAPSED_OUT = "Collapsed Output";

	//control flow vertex types
	public static final String BASE_BLOCK_VERTEX = "Base Block";
	public static final String PARENT_BLOCK_VERTEX = "Parent Block";
	public static final String GRANDPARENT_BLOCK_VERTEX = "Grandparent Block";
	public static final String CHILD_BLOCK_VERTEX = "Child Block";
	public static final String SIBLING_BLOCK_VERTEX = "Sibling Block";
	public static final String NULL_BLOCK_VERTEX = "Null Block";

	//for blocks that can't be categorized cleanly within a bsim neighborhood using 
	//ancestor/descendant relations
	public static final String BSIM_NEIGHBOR_VERTEX = "BSim Neighbor Block";

	//control flow  vertex attributes
	public static final String BLOCK_START = "Block Start";
	public static final String BLOCK_STOP = "Block Stop";
	public static final String CALL_STRING = "Call String";
	public static final String EMPTY_CALL_STRING = "(empty)";

	//control flow edge types
	public static final String TRUE_EDGE = "True";
	public static final String FALSE_EDGE = "False";
	public static final String CONTROL_FLOW_DEFAULT_EDGE = "Default";

	//copy signature attributes
	public static final String COPY_SIGNATURE = "Copy Signature";

	public static int DATAFLOW_WINDOW_SIZE = 3;
	public static final String DATAFLOW_PREFIX = "df";
	public static final String CONTROL_FLOW_PREFIX = "cf";
	public static final String COPY_PREFIX = "copy";

	public static final String OPTIONS_NAME = "BSim Feature Graph";

	static {
		vertexTypes.add(DEFAULT_VERTEX);
		vertexTypes.add(CONSTANT_VERTEX);
		vertexTypes.add(VARNODE_ADDRESS);
		vertexTypes.add(BASE_VARNODE_VERTEX);
		vertexTypes.add(SECONDARY_BASE_VARNODE_VERTEX);
		vertexTypes.add(FUNCTION_INPUT);
		vertexTypes.add(CONSTANT_FUNCTION_INPUT);
		vertexTypes.add(PCODE_OP_VERTEX);
		vertexTypes.add(VOID_BASE);
		vertexTypes.add(COLLAPSED_VARNODE);
		vertexTypes.add(COLLAPSED_OP);
		vertexTypes.add(BASE_BLOCK_VERTEX);
		vertexTypes.add(PARENT_BLOCK_VERTEX);
		vertexTypes.add(GRANDPARENT_BLOCK_VERTEX);
		vertexTypes.add(CHILD_BLOCK_VERTEX);
		vertexTypes.add(SIBLING_BLOCK_VERTEX);
		vertexTypes.add(NULL_BLOCK_VERTEX);
		vertexTypes.add(BSIM_NEIGHBOR_VERTEX);

		edgeTypes.add(DATAFLOW_IN);
		edgeTypes.add(DATAFLOW_OUT);
		edgeTypes.add(COLLAPSED_IN);
		edgeTypes.add(COLLAPSED_OUT);
		edgeTypes.add(TRUE_EDGE);
		edgeTypes.add(FALSE_EDGE);
		edgeTypes.add(CONTROL_FLOW_DEFAULT_EDGE);

	}

	public BSimFeatureGraphType() {
		super("BSim Feature Graph", "BSim Feature Graph", vertexTypes, edgeTypes);
	}

	@Override
	public String getOptionsName() {
		return OPTIONS_NAME;
	}

}
