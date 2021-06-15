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
package ghidra.dalvik.dex.inject;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.file.formats.android.dex.analyzer.DexAnalysisState;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Map Ghidra's generic ConstantPool interface onto the Dex specific constant pool 
 *
 */
public class ConstantPoolDex extends ConstantPool {

	private Program program;
	private DexHeader dexHeader;
	private DataTypeManager dtManager;

	public ConstantPoolDex(Program program) throws IOException {
		this.program = program;
		DexAnalysisState analysisState = DexAnalysisState.getState(program);
		dexHeader = analysisState.getHeader();
		dtManager = program.getDataTypeManager();
	}

	private void fillinField(int fieldID, boolean isStatic, Record res) {
		FieldIDItem fieldIDItem = dexHeader.getFields().get(fieldID);

		StringIDItem stringItem = dexHeader.getStrings().get(fieldIDItem.getNameIndex());
		res.tag = ConstantPool.POINTER_FIELD;
		res.token = stringItem.getStringDataItem().getString();

		if (isStatic) {
			String classString =
				DexUtil.convertTypeIndexToString(dexHeader, fieldIDItem.getClassIndex());
			String[] pathArray = DexUtil.convertClassStringToPathArray("", classString);
			if (pathArray != null) {
				res.token = pathArray[pathArray.length - 1] + '.' + res.token;
			}
		}

		DataType fieldDT = dexHeader.getDataType(program, fieldIDItem.getTypeIndex());
		res.type = new PointerDataType(fieldDT);
	}

	private void fillinArrayLength(Record res) {
		res.tag = ConstantPool.ARRAY_LENGTH;
		res.token = "length";
		res.type = IntegerDataType.dataType;
	}

	private String removeUniquifier(String name) {
		int len = name.length();
		if (len < 10 || name.charAt(len - 9) != '_') {
			return name;
		}
		char matchChar = name.charAt(len - 8);
		if (matchChar != '5' && matchChar != 'e') {
			return name;
		}
		if (name.charAt(len - 7) != '0') {
			return name;
		}
		return name.substring(0, len - 9);
	}

	private void fillinMethod(int methodID, boolean isStatic, Record res) {
		MethodIDItem methodIDItem = dexHeader.getMethods().get(methodID);
		Address addr = dexHeader.getMethodAddress(program, methodID);
		res.token = null;
		String namespaceString = null;
		if (addr != Address.NO_ADDRESS) {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
			if (symbol != null && symbol.getSource() != SourceType.DEFAULT) {
				res.token = symbol.getName();
				res.token = removeUniquifier(res.token);
				namespaceString = symbol.getParentNamespace().getName();
			}
		}
		if (res.token == null) {
			res.token = DexUtil.convertToString(dexHeader, methodIDItem.getNameIndex());
		}
		if (isStatic) {
			if (namespaceString == null) {
				String classString =
					DexUtil.convertTypeIndexToString(dexHeader, methodIDItem.getClassIndex());
				String[] pathArray = DexUtil.convertClassStringToPathArray("", classString);
				if (pathArray != null) {
					namespaceString = pathArray[pathArray.length - 1];
				}
			}
			if (namespaceString != null) {
				res.token = namespaceString + '.' + res.token;
			}
		}
		res.tag = ConstantPool.POINTER_METHOD;
		// The FunctionDefinition is constructed on the fly, essentially as an anonymous type
		// We use an internal naming scheme involding the the methodID to avoid name collisions
		String defName = res.token + '_' + Integer.toHexString(methodID);
		FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(defName, dtManager);
		res.type = new PointerDataType(funcDef);
		funcDef.setGenericCallingConvention(
			isStatic ? GenericCallingConvention.stdcall : GenericCallingConvention.thiscall);

		int prototypeIndex = methodIDItem.getProtoIndex() & 0xffff;
		PrototypesIDItem prototype = dexHeader.getPrototypes().get(prototypeIndex);
		DataType returnDataType =
			dexHeader.getDataType(program, (short) prototype.getReturnTypeIndex());
		funcDef.setReturnType(returnDataType);

		ArrayList<ParameterDefinition> paramDef = new ArrayList<>();
		if (!isStatic) {
			ParameterDefinitionImpl pDef =
				new ParameterDefinitionImpl("ref", Undefined4DataType.dataType, null);
			paramDef.add(pDef);
		}
		TypeList parameters = prototype.getParameters();
		if (parameters != null) {
			for (TypeItem parameterTypeItem : parameters.getItems()) {
				DataType parameterDataType =
					dexHeader.getDataType(program, parameterTypeItem.getType());
				ParameterDefinitionImpl pDef =
					new ParameterDefinitionImpl("", parameterDataType, null);
				paramDef.add(pDef);
			}
		}
		ParameterDefinition finalDefs[] = new ParameterDefinition[paramDef.size()];
		paramDef.toArray(finalDefs);
		funcDef.setArguments(finalDefs);
	}

	private void fillinString(int stringID, Record res) {
		StringIDItem stringIDItem = dexHeader.getStrings().get(stringID);
		res.tag = ConstantPool.STRING_LITERAL;
		res.setUTF8Data(stringIDItem.getStringDataItem().getString());
		res.type = PointerDataType.dataType;
	}

	private void fillinClass(short classID, Record res) {
//		ClassDefItem classDefItem = dexHeader.getClassDefs().get(classID);
		res.tag = ConstantPool.CLASS_REFERENCE;
		res.token = "<none>";
		if (classID == -1) {//java.lang.Object, no super class
			res.type = DataType.DEFAULT;
		}
		else {
			res.type = dexHeader.getDataType(program, classID);
			if (res.type instanceof Pointer) {
				res.token = ((Pointer) res.type).getDataType().getName();
			}
		}
	}

	private void fillinSuper(Record res) {
		res.tag = ConstantPool.POINTER_METHOD;
		res.token = "super";
		res.type = DataType.DEFAULT; // TODO: We could fill in the super-class of class whose method we are in
	}

	private void fillinInstanceOf(short classID, Record res) {
		res.tag = ConstantPool.INSTANCE_OF;
		res.token = "instanceof";
		if (classID == -1) {//java.lang.Object, no super class
			res.type = DataType.DEFAULT;
		}
		else {
			res.type = dexHeader.getDataType(program, classID);
		}
	}

	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		switch ((int) ref[1]) {
			case 0:					// Method invocation
				fillinMethod((int) ref[0], false, res);
				return res;
			case 1:					// Field lookup
				fillinField((int) ref[0], false, res);
				return res;
			case 2:					// Static field lookup
				fillinField((int) ref[0], true, res);
				return res;
			case 3:					// Static method
				fillinMethod((int) ref[0], true, res);
				return res;
			case 4:					// String literals
				fillinString((int) ref[0], res);
				return res;
			case 5:					// Class references
				fillinClass((short) ref[0], res);
				return res;
			case 6:
				fillinArrayLength(res);
				return res;
			case 7:
				fillinSuper(res);
				return res;
			case 8:
				fillinInstanceOf((short) ref[0], res);
				return res;
		}
		return null;
	}

}
