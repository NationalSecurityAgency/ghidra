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

import java.util.*;
import java.util.stream.Collectors;

import java.io.IOException;

import ghidra.app.util.bin.format.golang.GoFunctionMultiReturn;
import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;

@StructureMapping(structureName = "runtime.functype")
public class GoFuncType extends GoType {

	@FieldMapping
	private int inCount; // uint16

	@FieldMapping
	private int outCount; // uint16

	public GoFuncType() {
	}

	public boolean isVarArg() {
		return (outCount & 0x8000) != 0;
	}

	public int getInCount() {
		return inCount;
	}

	public int getOutCount() {
		return outCount & 0x7fff;
	}

	public int getParamCount() {
		return inCount + (outCount & 0x7fff);
	}

	public List<Address> getParamTypeAddrs() throws IOException {
		GoSlice slice = getParamListSlice();
		long[] typeOffsets = slice.readUIntList(programContext.getPtrSize());
		return Arrays.stream(typeOffsets)
				.mapToObj(programContext::getDataAddress)
				.collect(Collectors.toList());
	}

	private GoSlice getParamListSlice() {
		int count = getParamCount();
		return new GoSlice(getOffsetEndOfFullType(), count, count, programContext);
	}

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
				.collect(Collectors.toList());
	}

	@Override
	public void additionalMarkup() throws IOException {
		GoSlice slice = getParamListSlice();
		slice.markupArray(getStructureLabel() + "_paramlist", GoBaseType.class, true);
	}

	public String getFuncPrototypeString(String funcName) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append("func");
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
			sb.append(paramType.getBaseType().getNameString());
		}
		sb.append(")");
		if (!outParamTypes.isEmpty()) {
			sb.append(" (");
			for (int i = 0; i < outParamTypes.size(); i++) {
				GoType paramType = outParamTypes.get(i);
				if (i != 0) {
					sb.append(", ");
				}
				sb.append(paramType.getBaseType().getNameString());
			}
			sb.append(")");
		}
		return sb.toString();
	}

	@Override
	public DataType recoverDataType() throws IOException {
		String name = typ.getNameString();
		DataTypeManager dtm = programContext.getDTM();

		List<GoType> paramTypes = getParamTypes();
		List<GoType> inParamTypes = paramTypes.subList(0, inCount);
		List<GoType> outParamTypes = paramTypes.subList(inCount, paramTypes.size());

		List<ParameterDefinition> params = new ArrayList<>();
		for (int i = 0; i < inParamTypes.size(); i++) {
			GoType paramType = inParamTypes.get(i);
			DataType paramDT = paramType.recoverDataType();
			params.add(new ParameterDefinitionImpl(null, paramDT, null));
		}
		DataType returnDT;
		if (outParamTypes.size() == 0) {
			returnDT = VoidDataType.dataType;
		}
		else if (outParamTypes.size() == 1) {
			returnDT = outParamTypes.get(0).recoverDataType();
		}
		else {
			List<DataType> paramDataTypes = recoverTypes(outParamTypes);
			GoFunctionMultiReturn multiReturn = new GoFunctionMultiReturn(
				programContext.getRecoveredTypesCp(), name, paramDataTypes, dtm, null);
			returnDT = multiReturn.getStruct();
		}

		FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(
			programContext.getRecoveredTypesCp(), name, dtm);
		funcDef.setArguments(params.toArray(ParameterDefinition[]::new));
		funcDef.setReturnType(returnDT);

		return dtm.getPointer(funcDef);
	}

	private List<DataType> recoverTypes(List<GoType> types) throws IOException {
		List<DataType> result = new ArrayList<>();
		for (GoType type : types) {
			result.add(type.recoverDataType());
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
	public String toString() {
		try {
			return getFuncPrototypeString(null);
		}
		catch (IOException e) {
			return super.toString();
		}
	}

}
