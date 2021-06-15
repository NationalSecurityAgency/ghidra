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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import java.util.HashMap;
import java.util.Map;

/**
 * Enumerates the High Level Shader Language Register Type.
 * @see DataHighLevelShaderLanguageSymbolInternals
 */
public enum HLSLRegisterType {

	INVALID("INVALID_REG", -1),
	TEMP("TEMP", 0),
	INPUT("INPUT", 1),
	OUTPUT("OUTPUT", 2),
	INDEXABLE_TEMP("INDEXABLE_TEMP", 3),
	IMMEDIATE32("IMMEDIATE32", 4),
	IMMEDIATE64("IMMEDIATE64", 5),
	SAMPLER("SAMPLER", 6),
	RESOURCE("RESOURCE", 7),
	CONSTANT_BUFFER("CONSTANT_BUFFER", 8),
	IMMEDIATE_CONSTANT_BUFFER("IMMEDIATE_CONSTANT_BUFFER", 9),
	LABEL("LABEL", 10),
	INPUT_PRIMITIVEID("INPUT_PRIMITIVEID", 11),
	OUTPUT_DEPTH("OUTPUT_DEPTH", 12),
	NULL("NULL", 13),
	RASTERIZER("RASTERIZER", 14),
	OUTPUT_COVERAGE_MASK("OUTPUT_COVERAGE_MASK", 15),
	STREAM("STREAM", 16),
	FUNCTION_BODY("FUNCTION_BODY", 17),
	FUNCTION_TABLE("FUNCTION_TABLE", 18),
	INTERFACE("INTERFACE", 19),
	FUNCTION_INPUT("FUNCTION_INPUT", 20),
	FUNCTION_OUTPUT("FUNCTION_OUTPUT", 21),
	OUTPUT_CONTROL_POINT_ID("OUTPUT_CONTROL_POINT_ID", 22),
	INPUT_FORK_INSTANCE_ID("INPUT_FORK_INSTANCE_ID", 23),
	INPUT_JOIN_INSTANCE_ID("INPUT_JOIN_INSTANCE_ID", 24),
	INPUT_CONTROL_POINT("INPUT_CONTROL_POINT", 25),
	OUTPUT_CONTROL_POINT("OUTPUT_CONTROL_POINT", 26),
	INPUT_PATCH_CONSTANT("INPUT_PATCH_CONSTANT", 27),
	INPUT_DOMAIN_POINT("INPUT_DOMAIN_POINT", 28),
	THIS_POINTER("THIS_POINTER", 29),
	UNORDERED_ACCESS_VIEW("UNORDERED_ACCESS_VIEW", 30),
	THREAD_GROUP_SHARED_MEMORY("THREAD_GROUP_SHARED_MEMORY", 31),
	INPUT_THREAD_ID("INPUT_THREAD_ID", 32),
	INPUT_THREAD_GROUP_ID("INPUT_THREAD_GROUP_ID", 33),
	INPUT_THREAD_ID_IN_GROUP("INPUT_THREAD_ID_IN_GROUP", 34),
	INPUT_COVERAGE_MASK("INPUT_COVERAGE_MASK", 35),
	INPUT_THREAD_ID_IN_GROUP_FLATTENED("INPUT_THREAD_ID_IN_GROUP_FLATTENED", 36),
	INPUT_GS_INSTANCE_ID("INPUT_GS_INSTANCE_ID", 37),
	OUTPUT_DEPTH_GREATER_EQUA("OUTPUT_DEPTH_GREATER_EQUA", 38),
	OUTPUT_DEPTH_LESS_EQUAL("OUTPUT_DEPTH_LESS_EQUAL", 39),
	CYCLE_COUNTER("CYCLE_COUNTER", 40);

	private static final Map<Integer, HLSLRegisterType> BY_VALUE = new HashMap<>();
	static {
		for (HLSLRegisterType val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	public final String label;
	public final int value;

	@Override
	public String toString() {
		return label;
	}

	public static HLSLRegisterType fromValue(int val) {
		return BY_VALUE.getOrDefault(val, INVALID);
	}

	private HLSLRegisterType(String label, int value) {
		this.label = label;
		this.value = value;
	}

}
