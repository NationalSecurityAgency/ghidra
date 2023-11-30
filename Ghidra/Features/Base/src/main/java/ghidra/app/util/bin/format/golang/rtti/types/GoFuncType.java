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
package ghidra.app.util.bin.format.golang.rtti.types;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.golang.GoFunctionMultiReturn;
import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;

/**
 * A {@link GoType} structure that defines a function type.
 */
@StructureMapping(structureName = "runtime.functype")
public class GoFuncType extends GoType {

	/**
	 * Converts a ptr-to-ptr-to-funcdef to the base funcdef type.
	 * 
	 * @param dt ghidra {@link DataType}
	 * @return {@link FunctionDefinition} that was pointed to by specified data type, or null
	 */
	public static FunctionDefinition unwrapFunctionDefinitionPtrs(DataType dt) {
		return dt != null && dt instanceof Pointer ptrDT &&
			ptrDT.getDataType() instanceof Pointer ptrptrDT &&
			ptrptrDT.getDataType() instanceof FunctionDefinition funcDef ? funcDef : null;
	}

	@FieldMapping
	private int inCount; // uint16

	@FieldMapping
	private int outCount; // uint16

	public GoFuncType() {
		// empty
	}

	/**
	 * Returns true if this function type is defined to be vararg
	 * @return true if this function type is defined to be vararg
	 */
	public boolean isVarArg() {
		return (outCount & 0x8000) != 0;
	}

	/**
	 * Returns the number of inbound parameters
	 * @return number of inbound parameters
	 */
	public int getInCount() {
		return inCount;
	}

	/**
	 * Returns the number of outbound result values
	 * @return number of outbound result values
	 */
	public int getOutCount() {
		return outCount & 0x7fff;
	}

	/**
	 * Returns the total number of in and out parameters
	 * @return total number of in and out parameters
	 */
	public int getParamCount() {
		return inCount + (outCount & 0x7fff);
	}

	private List<Address> getParamTypeAddrs() throws IOException {
		GoSlice slice = getParamListSlice();
		long[] typeOffsets = slice.readUIntList(programContext.getPtrSize());
		return Arrays.stream(typeOffsets)
				.mapToObj(programContext::getDataAddress)
				.toList();
	}

	private GoSlice getParamListSlice() {
		int count = getParamCount();
		return new GoSlice(getOffsetEndOfFullType(), count, count, programContext);
	}

	/**
	 * Returns a list of {@link GoType}s for each parameter
	 * @return list of {@link GoType}s for each parameter
	 * @throws IOException if error read type info
	 */
	@Markup
	public List<GoType> getParamTypes() throws IOException {
		return getParamTypeAddrs().stream()
				.map(addr -> {
					try {
						return programContext.getGoType(addr);
					}
					catch (IOException e) {
						return null;
					}
				})
				.toList();
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException {
		GoSlice slice = getParamListSlice();
		slice.markupArray(getStructureLabel() + "_paramlist", getStructureNamespace(),
			GoBaseType.class, true, session);
	}

	/**
	 * Returns a string that describes the function type as a golang-ish function decl.
	 * 
	 * @param funcName optional name of a function
	 * @param receiverString optional receiver decl string
	 * @return golang func decl string
	 * @throws IOException if error reading parameter type info
	 */
	public String getFuncPrototypeString(String funcName, String receiverString)
			throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append("func");
		if (receiverString != null && !receiverString.isBlank()) {
			sb.append(" (").append(receiverString).append(")");
		}
		if (funcName != null && !funcName.isBlank()) {
			sb.append(" ").append(funcName);
		}
		sb.append("(");

		List<GoType> paramTypes = getParamTypes();
		List<GoType> inParamTypes = paramTypes.subList(0, inCount);
		List<GoType> outParamTypes = paramTypes.subList(inCount, paramTypes.size());
		for (int i = 0; i < inParamTypes.size(); i++) {
			GoType paramType = inParamTypes.get(i);
			if (i != 0) {
				sb.append(", ");
			}
			sb.append(paramType.getName());
		}
		sb.append(")");
		if (!outParamTypes.isEmpty()) {
			sb.append(" (");
			for (int i = 0; i < outParamTypes.size(); i++) {
				GoType paramType = outParamTypes.get(i);
				if (i != 0) {
					sb.append(", ");
				}
				sb.append(paramType.getName());
			}
			sb.append(")");
		}
		return sb.toString();
	}

	@Override
	public DataType recoverDataType() throws IOException {
		String name = getUniqueTypename();
		DataTypeManager dtm = programContext.getDTM();

		FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(
			programContext.getRecoveredTypesCp(getPackagePathString()), name, dtm);
		Pointer funcDefPtr = dtm.getPointer(funcDef);
		Pointer funcDefPtrPtr = dtm.getPointer(funcDefPtr);
		// pre-push empty funcdef type into cache to prevent endless recursive loops
		programContext.cacheRecoveredDataType(this, funcDefPtrPtr);

		List<GoType> paramTypes = getParamTypes();
		List<GoType> inParamTypes = paramTypes.subList(0, inCount);
		List<GoType> outParamTypes = paramTypes.subList(inCount, paramTypes.size());

		List<ParameterDefinition> params = new ArrayList<>();
		for (int i = 0; i < inParamTypes.size(); i++) {
			GoType paramType = inParamTypes.get(i);
			DataType paramDT = programContext.getRecoveredType(paramType);
			params.add(new ParameterDefinitionImpl(null, paramDT, null));
		}
		DataType returnDT;
		if (outParamTypes.size() == 0) {
			returnDT = VoidDataType.dataType;
		}
		else if (outParamTypes.size() == 1) {
			returnDT = programContext.getRecoveredType(outParamTypes.get(0));
		}
		else {
			List<DataType> paramDataTypes = recoverTypes(outParamTypes);
			GoFunctionMultiReturn multiReturn = new GoFunctionMultiReturn(
				programContext.getRecoveredTypesCp(getPackagePathString()), name, paramDataTypes,
				dtm, null);
			returnDT = multiReturn.getStruct();
		}

		funcDef.setArguments(params.toArray(ParameterDefinition[]::new));
		funcDef.setReturnType(returnDT);

		return funcDefPtrPtr;
	}

	private List<DataType> recoverTypes(List<GoType> types) throws IOException {
		List<DataType> result = new ArrayList<>();
		for (GoType type : types) {
			result.add(programContext.getRecoveredType(type));
		}
		return result;
	}

	@Override
	public boolean discoverGoTypes(Set<Long> discoveredTypes) throws IOException {
		if (!super.discoverGoTypes(discoveredTypes)) {
			return false;
		}
		for (GoType paramType : getParamTypes()) {
			if (paramType != null) {
				paramType.discoverGoTypes(discoveredTypes);
			}
		}
		return true;
	}

	@Override
	protected String getTypeDeclString() throws IOException {
		return getFuncPrototypeString(null, null);
	}

}
