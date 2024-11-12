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

import static ghidra.app.util.bin.format.golang.GoConstants.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.golang.rtti.GoSlice;
import ghidra.app.util.bin.format.golang.rtti.GoTypeManager;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/**
 * A {@link GoType} structure that defines a function type.
 */
@StructureMapping(structureName = {"runtime.functype", "internal/abi.FuncType"})
public class GoFuncType extends GoType {

	/**
	 * Converts a ptr-to-ptr-to-funcdef to the base funcdef type.
	 * 
	 * @param dt ghidra {@link DataType}
	 * @return {@link FunctionDefinition} that was pointed to by specified data type, or null
	 */
	public static FunctionDefinition unwrapFunctionDefinitionPtrs(DataType dt) {
		return dt != null && dt instanceof Pointer ptrDT &&
			ptrDT.getDataType() instanceof Structure closureStructDT &&
			closureStructDT.getNumComponents() > 1 &&
			closureStructDT.getComponent(0).getDataType() instanceof Pointer funcdefPtr &&
			funcdefPtr.getDataType() instanceof FunctionDefinition funcdef ? funcdef : null;
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
				.map(addr -> programContext.getGoTypes().getTypeUnchecked(addr))
				.toList();
	}

	@Override
	public void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		super.additionalMarkup(session);
		GoSlice slice = getParamListSlice();
		slice.markupArray(getStructureLabel() + "_paramlist", getStructureNamespace(),
			GoBaseType.class, true, session);
	}

	/**
	 * Returns a string that describes the function type as a golang-ish function decl.
	 * 
	 * @param funcName optional name of a function
	 * @return golang func decl string
	 */
	public String getFuncPrototypeString(String funcName) {
		if (funcName != null && !funcName.isBlank()) {
			funcName = " " + funcName;
		} else {
			funcName = "";
		}
		return "func%s%s".formatted(funcName, getParamListString());
	}
	
	public String getParamListString() {
		try {
			StringBuilder sb = new StringBuilder();
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
				sb.append(" ");
				if (outParamTypes.size() > 1) {
					sb.append("(");
				}
				for (int i = 0; i < outParamTypes.size(); i++) {
					GoType paramType = outParamTypes.get(i);
					if (i != 0) {
						sb.append(", ");
					}
					sb.append(paramType.getName());
				}
				if (outParamTypes.size() > 1) {
					sb.append(")");
				}
			}
			return sb.toString();
		} catch (IOException e) {
			return "(???)";
		}
	}
	
	public static String getMissingFuncPrototypeString(String funcName, String genericsString) {
		genericsString = genericsString == null || genericsString.isEmpty() ? "" : "[" + genericsString + "]";
		return "func %s%s(???)".formatted(funcName, genericsString);
	}

	@Override
	public DataType recoverDataType(GoTypeManager goTypes) throws IOException {
		DataTypeManager dtm = goTypes.getDTM();
		String name = goTypes.getTypeName(this);
		CategoryPath cp = goTypes.getCP(this);

		StructureDataType struct = new StructureDataType(cp, name, (int) typ.getSize(), dtm);
		DataType structPtr = dtm.getPointer(struct);

		FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(cp, name + "_F", dtm);
		struct.replace(0, dtm.getPointer(funcDef), -1, "F", null);
		struct.add(new ArrayDataType(goTypes.getUint8DT(), 0), "context", null);
		struct.setToDefaultPacking();

		// pre-push an partially constructed struct into the cache to prevent endless recursive loops
		goTypes.cacheRecoveredDataType(this, structPtr);

		List<GoType> paramTypes = getParamTypes();
		List<GoType> inParamTypes = paramTypes.subList(0, inCount);
		List<GoType> outParamTypes = paramTypes.subList(inCount, paramTypes.size());

		List<ParameterDefinition> params = new ArrayList<>();
		params.add(
			new ParameterDefinitionImpl(GOLANG_CLOSURE_CONTEXT_NAME, dtm.getPointer(struct), null));

		for (GoType paramType : inParamTypes) {
			DataType paramDT = goTypes.getGhidraDataType(paramType);
			params.add(new ParameterDefinitionImpl(null, paramDT, null));
		}

		DataType returnDT;
		if (outParamTypes.size() == 0) {
			returnDT = VoidDataType.dataType;
		}
		else if (outParamTypes.size() == 1) {
			returnDT = goTypes.getGhidraDataType(outParamTypes.get(0));
		}
		else {
			List<DataType> paramDataTypes = new ArrayList<>();
			for (GoType outParamType : outParamTypes) {
				paramDataTypes.add(goTypes.getGhidraDataType(outParamType));
			}
			returnDT = goTypes.getFuncMultiReturn(paramDataTypes);
		}

		funcDef.setArguments(params.toArray(ParameterDefinition[]::new));
		funcDef.setReturnType(returnDT);


		// TODO: typ.getSize() should be ptrsize, and struct size should also be ptrsize

		return structPtr;
	}

	public FunctionDefinition getFunctionSignature(GoTypeManager goTypes) throws IOException {
		DataType dt = goTypes.getGhidraDataType(this);
		FunctionDefinition funcdef = dt instanceof Pointer ptrDT &&
			ptrDT.getDataType() instanceof Structure closureStructDT &&
			closureStructDT.getNumComponents() > 1 &&
			closureStructDT.getComponent(0).getDataType() instanceof Pointer funcdefPtr &&
			funcdefPtr.getDataType() instanceof FunctionDefinition fd ? fd : null;

		if (funcdef == null) {
			throw new IOException("Unable to extract function sig for " + this.toString());
		}

		List<ParameterDefinition> newArgs = new ArrayList<>();
		ParameterDefinition[] oldArgs = funcdef.getArguments();
		for (int i = 1; i < oldArgs.length; i++) {
			newArgs.add(oldArgs[i]);
		}

		FunctionDefinitionDataType funcsig =
			new FunctionDefinitionDataType(funcdef.getName(), goTypes.getDTM());
		try {
			funcsig.setCallingConvention(funcdef.getCallingConventionName());
		}
		catch (InvalidInputException e) {
			// ignore
		}
		funcsig.setReturnType(funcdef.getReturnType());
		funcsig.setArguments(newArgs.toArray(ParameterDefinition[]::new));

		return funcsig;
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
		String baseTypeName = getSymbolName().getBaseTypeName();
		String declStr = getFuncPrototypeString(null);
		return baseTypeName.startsWith("func(") ? "type %s".formatted(declStr)
				: "type %s %s".formatted(baseTypeName, declStr);
	}

	@Override
	public boolean isValid() {
		return super.isValid() && typ.getSize() == programContext.getPtrSize();
	}

}

