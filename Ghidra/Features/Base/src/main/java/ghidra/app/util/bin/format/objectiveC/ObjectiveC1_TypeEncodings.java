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
package ghidra.app.util.bin.format.objectiveC;

import java.util.*;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;

public final class ObjectiveC1_TypeEncodings {
	public final static char _C_ID = '@';
	public final static char _C_CLASS = '#';
	public final static char _C_SEL = ':';
	public final static char _C_CHR = 'c';
	public final static char _C_UCHR = 'C';
	public final static char _C_SHT = 's';
	public final static char _C_USHT = 'S';
	public final static char _C_INT = 'i';
	public final static char _C_UINT = 'I';
	public final static char _C_LNG = 'l';
	public final static char _C_ULNG = 'L';
	public final static char _C_LNG_LNG = 'q';
	public final static char _C_ULNG_LNG = 'Q';
	public final static char _C_FLT = 'f';
	public final static char _C_DBL = 'd';
	public final static char _C_BOOL = 'B';
	public final static char _C_VOID = 'v';
	public final static char _C_UNDEF = '?';
	public final static char _C_PTR = '^';
	public final static char _C_CHARPTR = '*';
	public final static char _C_ATOM = '%';

	public final static char _C_ARY_B = '[';
	public final static char _C_ARY_E = ']';
	public final static char _C_UNION_B = '(';
	public final static char _C_UNION_E = ')';
	public final static char _C_STRUCT_B = '{';
	public final static char _C_STRUCT_E = '}';
	public final static char _C_VECTOR = '!';
//	public final static char _C_GCINVISIBLE     = '!'; TODO which is correct??

	// STRUCTURE ONLY TYPES
	//

	public final static char _C_BFLD = 'b';

	// MODIFIERS
	//

	public final static char _C_CONST = 'r';
	public final static char _C_IN = 'n';
	public final static char _C_INOUT = 'N';
	public final static char _C_OUT = 'o';
	public final static char _C_BYCOPY = 'O';
	public final static char _C_BYREF = 'R';
	public final static char _C_ONEWAY = 'V';
	public final static char _C_ATOMIC = 'A';

	private final static String ANONYMOUS_PREFIX = "Anonymous";

	private enum AnonymousTypes {
		STRUCTURE(ANONYMOUS_PREFIX + "Structure"),
		UNION(ANONYMOUS_PREFIX + "Union"),
		BIT_FIELD_UNION(ANONYMOUS_PREFIX + "BitField");

		private String string;

		AnonymousTypes(String string) {
			this.string = string;
		}

		@Override
		public String toString() {
			return string;
		}
	}

	private List<Composite> anonymousCompositeList = new ArrayList<Composite>();
	private Map<AnonymousTypes, Integer> anonymousIndexMap = new HashMap<AnonymousTypes, Integer>();

	private int pointerSize;
	private CategoryPath categoryPath;

	public ObjectiveC1_TypeEncodings(int pointerSize, CategoryPath categoryPath) {
		this.pointerSize = pointerSize;
		this.categoryPath = categoryPath;

		for (AnonymousTypes type : AnonymousTypes.values()) {
			anonymousIndexMap.put(type, 0);
		}
	}

	public void processMethodSignature(Program program, Address methodAddress,
			String mangledSignature, ObjectiveC_MethodType methodType) {
		Function method = program.getListing().getFunctionAt(methodAddress);
		if (method == null) {
			return;//function might not have been created, prevents NPE in datatype
		}
		StringBuffer buffer = new StringBuffer(mangledSignature);
		DataType returnType = parseDataType(buffer);

		FunctionDefinitionDataType sig = new FunctionDefinitionDataType(method, true);

		if (returnType != null) {
			sig.setReturnType(returnType);
		}

		int totalSize = parseNumber(buffer);

		ArrayList<ParameterDefinition> args = new ArrayList<ParameterDefinition>();
		while (buffer.length() > 0) {
			DataType paramDT = parseDataType(buffer);

			//TODO we have to read the parameter offset, even if we do not use it!
			//int parameterOffset = parseNumber(buffer);
			if(Character.isDigit(buffer.charAt(0))) {
				parseNumber(buffer);
			}

			ArrayList<DataType> matchingDataTypes = new ArrayList<DataType>();
			program.getDataTypeManager().findDataTypes(paramDT.getName(), matchingDataTypes);
			if (matchingDataTypes.size() == 1) {
				paramDT = matchingDataTypes.get(0);
			}
			args.add(new ParameterDefinitionImpl(null, paramDT, null));
		}
		sig.setArguments(args.toArray(new ParameterDefinition[args.size()]));

		new ApplyFunctionSignatureCmd(methodAddress, sig, SourceType.ANALYSIS).applyTo(program);

		StringBuffer commentBuffer = new StringBuffer();
		commentBuffer.append("Function Stack Size: 0x" + Integer.toHexString(totalSize) + " bytes");

		if (method.getComment() == null) {
			method.setComment(commentBuffer.toString());
		}
	}

	public FunctionSignature toFunctionSignature(String methodName, String mangledSignature) {
		FunctionDefinitionDataType fSig = new FunctionDefinitionDataType(methodName);

		StringBuffer buffer = new StringBuffer(mangledSignature);

		DataType returnType = parseDataType(buffer);
		fSig.setReturnType(returnType);

		int totalStackSize = parseNumber(buffer);
		fSig.setComment("Function Stack Size: 0x" + Integer.toHexString(totalStackSize) + " bytes");

		List<ParameterDefinition> arguments = new ArrayList<ParameterDefinition>();

		while (buffer.length() > 0) {
			DataType paramDT = parseDataType(buffer);

			parseNumber(buffer); // need to consume parameterOffset - but not used

			//String name = "param_"+parameterOffset;

			String name = null;

			ParameterDefinition parameter = new ParameterDefinitionImpl(name, paramDT, null);
			arguments.add(parameter);
		}

		fSig.setArguments(arguments.toArray(new ParameterDefinition[arguments.size()]));

		return fSig;
	}

	public void processInstanceVariableSignature(Program program, Address instanceVariableAddress,
			String mangledType, int instanceVariableSize) {
/* TODO
 * check to make sure there is room... and does not bump into another item
 * check to see if consumes label

		StringBuffer buffer = new StringBuffer(type);
		DataType dt = parseDataType(buffer);

		program.getListing().clearCodeUnits(address, address.add(dt.getLength()));
		try {
			program.getListing().createData(address, dt);
		}
		catch (Exception e) {
			e.printStackTrace();//TODO
		}
*/
	}

	public String processInstanceVariableSignature(String name, String mangledType) {
		StringBuffer buffer = new StringBuffer(mangledType);
		DataType dt = parseDataType(buffer);
		return dt.getDisplayName() + " " + name;
	}

	private DataType parseDataType(StringBuffer buffer) {
		DataType dt = createProperDataType(buffer);
		try {
			dt.setCategoryPath(categoryPath);
		}
		catch (DuplicateNameException e) {
		}
		return dt;
	}

	private DataType createTypeDef(String name) {
		switch (pointerSize) {
			case 4:
				return new TypedefDataType(name, new DWordDataType());
			case 8:
				return new TypedefDataType(name, new QWordDataType());
		}
		throw new RuntimeException("Invalid pointer size specified.");
	}

	private DataType createProperDataType(StringBuffer buffer) {
		switch (buffer.charAt(0)) {
			case _C_ID: {
				buffer.deleteCharAt(0);
				String quotedName = parseQuotedName(buffer);
				if (quotedName != null) {
					DataType quoteNameTypeDef = createTypeDef(quotedName);
					return PointerDataType.getPointer(quoteNameTypeDef, pointerSize);
				}
				return createTypeDef("ID");
			}
			case _C_CLASS: {
				buffer.deleteCharAt(0);
				return createTypeDef("CLASS");
			}
			case _C_SEL: {
				buffer.deleteCharAt(0);
				return createTypeDef("SEL");
			}
			case _C_CHR: {
				buffer.deleteCharAt(0);
				return new CharDataType();
			}
			case _C_UCHR: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("unsigned char", new CharDataType());
			}
			case _C_SHT: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("short", new WordDataType());
			}
			case _C_USHT: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("unsigned short", new WordDataType());
			}
			case _C_INT: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("int", new DWordDataType());
			}
			case _C_UINT: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("unsigned int", new DWordDataType());
			}
			case _C_LNG: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("long", new QWordDataType());
			}
			case _C_ULNG: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("unsigned long", new QWordDataType());
			}
			case _C_LNG_LNG: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("long long", new QWordDataType());
			}
			case _C_ULNG_LNG: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("unsigned long long", new QWordDataType());
			}
			case _C_FLT: {
				buffer.deleteCharAt(0);
				return new FloatDataType();
			}
			case _C_DBL: {
				buffer.deleteCharAt(0);
				return new DoubleDataType();
			}
			case _C_BOOL: {
				buffer.deleteCharAt(0);
				return new TypedefDataType("bool", new DWordDataType());
			}
			case _C_VOID: {
				buffer.deleteCharAt(0);
				return new VoidDataType();
			}
			case _C_UNDEF: {
				buffer.deleteCharAt(0);
				return new Undefined4DataType();
			}
			case _C_PTR: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return PointerDataType.getPointer(dt, pointerSize);
			}
			case _C_CHARPTR: {
				buffer.deleteCharAt(0);
				return PointerDataType.getPointer(new CharDataType(), pointerSize);
			}
			case _C_ATOM: {
				throw new UnsupportedOperationException("atom not supported");
			}
			case _C_ARY_B: {
				buffer.deleteCharAt(0);//remove _C_ARY_B
				int nElements = parseNumber(buffer);
				DataType dt = parseDataType(buffer);
				buffer.deleteCharAt(0);//remove _C_ARY_E
				if (nElements > 0) {
					return new ArrayDataType(dt, nElements, dt.getLength());
				}
				//fabricate using a pointer instead of an array
				if (dt instanceof Pointer) {
					return dt;
				}
				return PointerDataType.getPointer(dt, pointerSize);
			}
			case _C_UNION_B: {
				buffer.deleteCharAt(0);//remove _C_UNION_B
				String name = parseCompositeName(buffer, _C_UNION_E, AnonymousTypes.UNION);
				UnionDataType union = new UnionDataType(name);
				while (buffer.charAt(0) != _C_UNION_E) {
					DataType dt = parseDataType(buffer);
					union.add(dt);
				}
				buffer.deleteCharAt(0);//remove _C_UNION_E
				return checkForExistingAnonymousEquivalent(union);
			}
			case _C_STRUCT_B: {
				buffer.deleteCharAt(0);//remove _C_STRUCT_B
				String name = parseCompositeName(buffer, _C_STRUCT_E, AnonymousTypes.STRUCTURE);
				StructureDataType struct = new StructureDataType(name, 0);
				while (buffer.charAt(0) != _C_STRUCT_E) {
					String fieldName = parseQuotedName(buffer);
					String comment = null;
					if (buffer.charAt(0) == _C_BFLD) {//this is a structure of bit fields... push name back onto buffer
						reinsertName(buffer, fieldName);
						Union bitFieldUnion = parseBitFields(buffer);
						DataType dt = checkForExistingAnonymousEquivalent(bitFieldUnion);
						struct.add(dt, fieldName, comment);
					}
					else {
						DataType dt = parseDataType(buffer);
						struct.add(dt, fieldName, comment);
					}
				}
				buffer.deleteCharAt(0);//remove _C_STRUCT_E
				if (struct.getLength() == 0) {
					struct.add(DataType.DEFAULT);
				}
				DataType dt = checkForExistingAnonymousEquivalent(struct);
				/*
				if (dt.getLength() == 0) {
					return PointerDataType.getPointer(dt, pointerSize); 
				}
				*/
				return dt;
			}
			case _C_VECTOR: {
				throw new UnsupportedOperationException("vector not supported");
			}
			case _C_CONST: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return new TypedefDataType("const " + dt.getDisplayName(), dt);
			}
			case _C_IN: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return new TypedefDataType("IN " + dt.getDisplayName(), dt);
			}
			case _C_INOUT: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return new TypedefDataType("INOUT " + dt.getDisplayName(), dt);
			}
			case _C_OUT: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return new TypedefDataType("OUT " + dt.getDisplayName(), dt);
			}
			case _C_BYCOPY: {
				buffer.deleteCharAt(0);
				return parseDataType(buffer);
			}
			case _C_BYREF: {
				buffer.deleteCharAt(0);
				return parseDataType(buffer);
			}
			case _C_ONEWAY: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return new TypedefDataType("ONEWAY " + dt.getDisplayName(), dt);
			}
			case _C_ATOMIC: {
				buffer.deleteCharAt(0);
				DataType dt = parseDataType(buffer);
				return new TypedefDataType("ATOMIC " + dt.getDisplayName(), dt);
			}
		}
		throw new UnsupportedOperationException("Unsupported Objective C type encoding: " + buffer.charAt(0));
	}

	private Union parseBitFields(StringBuffer buffer) {
		//
		//NOTE:
		//Ghidra does not support bit fields, so we
		//simulate it by creating a union of the bit fields.
		//
		Union bitFieldUnion =
			new UnionDataType(getUniqueAnonymousTypeName(AnonymousTypes.BIT_FIELD_UNION));
		try {
			bitFieldUnion.setCategoryPath(categoryPath);
		}
		catch (DuplicateNameException e) {
		}

		List<String> names = new ArrayList<String>();
		int defaultFieldNameIndex = 0;

		int totalBits = 0;

		while (true) {
			String name = parseQuotedName(buffer);
			if (buffer.charAt(0) != _C_BFLD) {
				reinsertName(buffer, name);
				break;
			}
			if (name == null) {
				name = "bitField" + (defaultFieldNameIndex++);
			}
			buffer.deleteCharAt(0);//_C_BFLD
			int nBits = parseNumber(buffer);
			names.add(name + "_" + nBits);
			totalBits += nBits;
		}

		DataType dt = getBitFieldDataType(totalBits);
		try {
			dt.setCategoryPath(categoryPath);
		}
		catch (DuplicateNameException e) {
		}

		for (String name : names) {
			bitFieldUnion.add(dt, name, null);
		}
		return bitFieldUnion;
	}

	private DataType getBitFieldDataType(int nBits) {
		int nRemainder = (nBits % 8) == 0 ? 0 : 8 - (nBits % 8);
		int nBytes = (nBits + nRemainder) / 8;
		switch (nBytes) {
			case 1:
				return new TypedefDataType("OneByteBitField", new ByteDataType());
			case 2:
				return new TypedefDataType("TwoByteBitField", new WordDataType());
			case 3:
			case 4:
				return new TypedefDataType("FourByteBitField", new DWordDataType());
			case 5:
			case 6:
			case 7:
			case 8:
				return new TypedefDataType("EightByteBitField", new QWordDataType());
		}
		throw new IllegalArgumentException();
	}

	private DataType checkForExistingAnonymousEquivalent(Composite composite) {
		if (composite.getName().startsWith(ANONYMOUS_PREFIX)) {
			for (Composite anonynousComposite : anonymousCompositeList) {
				if (anonynousComposite.isEquivalent(composite)) {
					return anonynousComposite;
				}
			}
		}
		anonymousCompositeList.add(composite);
		return composite;
	}

	private String parseCompositeName(StringBuffer buffer, char endCompositeChar,
			AnonymousTypes type) {
		if (buffer.charAt(0) == _C_UNDEF) {
			buffer.deleteCharAt(0);//remove _C_UNDEF
			if (buffer.charAt(0) == '=') {
				buffer.deleteCharAt(0);//remove '='
			}
			return getUniqueAnonymousTypeName(type);
		}

		int endCompositePos = buffer.indexOf("" + endCompositeChar);
		int equalPos = buffer.indexOf("=");

		if (equalPos >= 0 && equalPos < endCompositePos) {
			String name = buffer.substring(0, equalPos);
			buffer.delete(0, equalPos);
			buffer.deleteCharAt(0);//remove '='
			return name;
		}

		if (endCompositePos >= 0) {
			String name = buffer.substring(0, endCompositePos);
			buffer.delete(0, endCompositePos);
			return name;
		}

		throw new IllegalArgumentException("Name cannot be null.");
	}

	synchronized private String getUniqueAnonymousTypeName(AnonymousTypes type) {
		int index = anonymousIndexMap.get(type);
		anonymousIndexMap.put(type, index + 1);
		return type.toString() + index;
	}

	private String parseQuotedName(StringBuffer buffer) {
		if (buffer.charAt(0) == '\"') {
			int endquote = buffer.indexOf("\"", 1);
			String name = buffer.substring(1, endquote);
			buffer.delete(0, endquote + 1);
			return name;
		}
		return null;
	}

	private void reinsertName(StringBuffer buffer, String fieldName) {
		if (fieldName != null) {
			buffer.insert(0, '\"' + fieldName + '\"');
		}
	}

	private int parseNumber(StringBuffer buffer) {
		// TODO: figure out why we see an ID (@) immediately followed by unknown (?) [as in @?]
		// and then fix this the right way; for now we just discard the unknown whilst looking for the offset
		if (buffer.charAt(0) == _C_UNDEF) {
			buffer.deleteCharAt(0);
		}
		StringBuffer numberBuffer = new StringBuffer();
		while (buffer.length() > 0 && Character.isDigit(buffer.charAt(0))) {
			numberBuffer.append(buffer.charAt(0));
			buffer.deleteCharAt(0);
		}
		return Integer.parseInt(numberBuffer.toString());
	}
}
