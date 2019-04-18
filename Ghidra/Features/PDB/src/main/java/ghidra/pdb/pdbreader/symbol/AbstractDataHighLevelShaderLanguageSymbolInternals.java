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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Internals of the High Level Shader Language symbol.
 * <P>
 * Note: we have guessed that HLSL means High Level Shader Language.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractDataHighLevelShaderLanguageSymbolInternals
		extends AbstractSymbolInternals {

	protected static final String regTypeHLSL[] = { "TEMP", "INPUT", "OUTPUT", "INDEXABLE_TEMP",
		"IMMEDIATE32", "IMMEDIATE64", "SAMPLER", "RESOURCE", "CONSTANT_BUFFER",
		"IMMEDIATE_CONSTANT_BUFFER", "LABEL", "INPUT_PRIMITIVEID", "OUTPUT_DEPTH", "NULL",
		"RASTERIZER", "OUTPUT_COVERAGE_MASK", "STREAM", "FUNCTION_BODY", "FUNCTION_TABLE",
		"INTERFACE", "FUNCTION_INPUT", "FUNCTION_OUTPUT", "OUTPUT_CONTROL_POINT_ID",
		"INPUT_FORK_INSTANCE_ID", "INPUT_JOIN_INSTANCE_ID", "INPUT_CONTROL_POINT",
		"OUTPUT_CONTROL_POINT", "INPUT_PATCH_CONSTANT", "INPUT_DOMAIN_POINT", "THIS_POINTER",
		"UNORDERED_ACCESS_VIEW", "THREAD_GROUP_SHARED_MEMORY", "INPUT_THREAD_ID",
		"INPUT_THREAD_GROUP_ID", "INPUT_THREAD_ID_IN_GROUP", "INPUT_COVERAGE_MASK",
		"INPUT_THREAD_ID_IN_GROUP_FLATTENED", "INPUT_GS_INSTANCE_ID", "OUTPUT_DEPTH_GREATER_EQUAL",
		"OUTPUT_DEPTH_LESS_EQUAL", "CYCLE_COUNTER" };

	//==============================================================================================
	protected int typeIndex;
	protected long dataOffset;
	protected int registerType;
	protected AbstractString name;

	//==============================================================================================
	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractDataHighLevelShaderLanguageSymbolInternals(AbstractPdb pdb) {
		super(pdb);
	}

	public long getDataOffset() {
		return dataOffset;
	}

	public String getRegisterType() {
		if (registerType >= 0 && registerType < regTypeHLSL.length) {
			return regTypeHLSL[registerType];
		}
		return "INVALID_REG";
	}

	public int getTypeIndex() {
		return typeIndex;
	}

	public String getName() {
		return name.get();
	}

	@Override
	protected void create() {
		name = new StringUtf8Nt();
	}

}
