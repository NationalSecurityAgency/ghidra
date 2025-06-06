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
package ghidra.app.util.pdb;

import java.util.*;

import ghidra.app.util.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.pdb.classtype.*;
import ghidra.app.util.pdb.pdbapplicator.CppCompositeType;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

/**
 * Class to create the cvf4 program
 */
abstract public class ProgramCreator {

	protected final static Pointer pointer = new PointerDataType();

	protected final static DataType voidT = VoidDataType.dataType;
	protected final static DataType charT = CharDataType.dataType;
	protected final static DataType shortT = ShortDataType.dataType;
	protected final static DataType intT = IntegerDataType.dataType;
	protected final static DataType unsignedT = UnsignedIntegerDataType.dataType;
	protected final static DataType longT = LongDataType.dataType;
	protected final static DataType longlongT = LongLongDataType.dataType;
	protected final static DataType floatT = FloatDataType.dataType;
	protected final static DataType doubleT = DoubleDataType.dataType;
	protected final static DataType longdoubleT = LongDoubleDataType.dataType;
	protected final static DataType pcharT = new PointerDataType(charT);
	protected final static DataType pvoidT = new PointerDataType(voidT);
	protected final static FunctionDefinitionDataType fvoidvoidT = new FunctionDefinitionDataType(
		CategoryPath.ROOT, "_func", intT.getDataTypeManager());
	protected final static FunctionDefinitionDataType fintvoidT = new FunctionDefinitionDataType(
		CategoryPath.ROOT, "_func", intT.getDataTypeManager());
	protected final static FunctionDefinitionDataType fintintT = new FunctionDefinitionDataType(
		CategoryPath.ROOT, "_func", intT.getDataTypeManager());
	protected final static FunctionDefinitionDataType fpvoidunsignedT =
		new FunctionDefinitionDataType(
			CategoryPath.ROOT, "_func", intT.getDataTypeManager());

	static {
		try {
			ParameterDefinition parameterDefinition;

			fvoidvoidT.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
			fintvoidT.setReturnType(voidT);
			fintvoidT.setArguments(new ParameterDefinition[] {});
			DataTypeNamingUtil.setMangledAnonymousFunctionName(fvoidvoidT);

			fintvoidT.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
			fintvoidT.setReturnType(intT);
			fintvoidT.setArguments(new ParameterDefinition[] {});
			DataTypeNamingUtil.setMangledAnonymousFunctionName(fintvoidT);

			fintintT.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
			fintintT.setReturnType(intT);
			parameterDefinition = new ParameterDefinitionImpl("val", intT, "");
			fintintT.setArguments(new ParameterDefinition[] { parameterDefinition });
			DataTypeNamingUtil.setMangledAnonymousFunctionName(fintintT);

			fpvoidunsignedT.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
			fpvoidunsignedT.setReturnType(pvoidT);
			parameterDefinition = new ParameterDefinitionImpl("val", unsignedT, "");
			fintintT.setArguments(new ParameterDefinition[] { parameterDefinition });
			DataTypeNamingUtil.setMangledAnonymousFunctionName(fpvoidunsignedT);
		}
		catch (InvalidInputException e) {
			//
		}
	}

	protected final ClassFieldAttributes publicVirtualAttributes =
		ClassFieldAttributes.get(Access.PUBLIC, Property.VIRTUAL);
	protected static ClassFieldAttributes publicDirectAttributes =
		ClassFieldAttributes.get(Access.PUBLIC, Property.BLANK);
	protected final ClassFieldAttributes protectedVirtualAttributes =
		ClassFieldAttributes.get(Access.PROTECTED, Property.VIRTUAL);
	protected static ClassFieldAttributes protectedDirectAttributes =
		ClassFieldAttributes.get(Access.PROTECTED, Property.BLANK);
	protected final ClassFieldAttributes privateVirtualAttributes =
		ClassFieldAttributes.get(Access.PRIVATE, Property.VIRTUAL);
	protected static ClassFieldAttributes privateDirectAttributes =
		ClassFieldAttributes.get(Access.PRIVATE, Property.BLANK);

	protected static CppCompositeType createStruct(DataTypeManager dtm, String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm);
		SymbolPath symbolPath = new SymbolPath(name);
		String mangledName = createMangledName(name, ClassKey.STRUCT);
		return CppCompositeType.createCppStructType(CategoryPath.ROOT, symbolPath, composite, name,
			mangledName, size);
	}

	protected static String createMangledName(String className, ClassKey key) {
		StringBuilder builder = new StringBuilder();
		builder.append(".?A");
		switch (key) {
			case UNION:
				builder.append('T');
				break;
			case STRUCT:
				builder.append('U');
				break;
			case CLASS:
				builder.append('V');
				break;
			default:
				String msg = "Cannot handle type during testing" + key;
				Msg.error(null, msg);
				throw new AssertException(msg);
		}
		builder.append(className);
		builder.append("@@");
		return builder.toString();
	}

	/**
	 * Modifies an original expected result to look like a result that used speculative
	 * placement of virtual base classes
	 * @param original the original result
	 * @return the result with the modifications
	 */
	protected static String convertCommentsToSpeculative(String original) {
		return original.replace("Virtual Base", "Virtual Base - Speculative Placement");
	}

	/**
	 * Takes an original expected result, and at the specified starting line ('\n' delimited)
	 * index, replace the remaing expected result with the replacement String (can be multiple
	 * lines)
	 * @param orig the original expected result
	 * @param startLine the line to start the replacement
	 * @param replacement the String used to replace the remainder of the original String
	 * @return the result
	 */
	protected static String doReplacement(String orig, int startLine, String replacement) {
		List<String> lines = List.of(orig.split("\\n"));
		List<String> newLines = lines.subList(0, startLine);
		return String.join("\n", newLines) + "\n" + replacement;
	}

	private String programName;
	private String languageId;
	private String compilerSpec;
	private AddressNameLength sections[];
	private AddressNameBytes vbtInfo[];
	private AddressNameBytes vftInfo[];
	private AddressNameBytes functionInfo[];

	public static SymbolPath sp(String s) {
		return new SymbolPath(SymbolPathParser.parse(s));
	}

	public ProgramCreator(String programName, String languageId, String compilerSpec,
			AddressNameLength[] sections, AddressNameBytes[] vbtInfo, AddressNameBytes[] vftInfo,
			AddressNameBytes[] functionInfo) {
		this.programName = programName;
		this.languageId = languageId;
		this.compilerSpec = compilerSpec;
		this.sections = sections;
		this.vbtInfo = vbtInfo;
		this.vftInfo = vftInfo;
		this.functionInfo = functionInfo;
	}

	abstract protected List<DataType> getRegularTypes(DataTypeManager dtm) throws PdbException;

	abstract protected List<CppCompositeType> getCppTypes(DataTypeManager dtm) throws PdbException;

	public ProgramTestArtifacts create() throws Exception {

		MockPdb pdb = new MockPdb();

		ProgramBuilder builder =
			new ProgramBuilder(programName, languageId, compilerSpec, this);

		for (AddressNameLength info : sections) {
			builder.createMemory(info.name(), info.addr(), info.length());
		}

		Map<String, Address> addressByMangled = getAddressByMangledName(builder);

		createVxTables(builder, pdb);

		addTypeInfo(builder, pdb);

		addFunctionInfo(builder, pdb);

		ProgramDB program = builder.getProgram();

		return new ProgramTestArtifacts(program, pdb, addressByMangled);
	}

	public Map<String, Address> getAddressByMangledName(ProgramBuilder builder) {
		Map<String, Address> addressesByMangledName = new HashMap<>();
		for (AddressNameBytes addressNameBytes : vbtInfo) {
			Address addr = builder.addr(addressNameBytes.addr());
			addressesByMangledName.put(addressNameBytes.name(), addr);
		}
		for (AddressNameBytes addressNameBytes : vftInfo) {
			Address addr = builder.addr(addressNameBytes.addr());
			addressesByMangledName.put(addressNameBytes.name(), addr);
		}
		return addressesByMangledName;
	}

	private void createVxTables(ProgramBuilder builder, MockPdb pdb) throws Exception {
		for (AddressNameBytes tableInfo : vbtInfo) {
			builder.setBytes(tableInfo.addr(), tableInfo.bytes());
			pdb.addSymbol(builder.addr(tableInfo.addr()), tableInfo.name());
		}
		for (AddressNameBytes tableInfo : vftInfo) {
			builder.setBytes(tableInfo.addr(), tableInfo.bytes());
			pdb.addSymbol(builder.addr(tableInfo.addr()), tableInfo.name());
		}
	}

	private void addTypeInfo(ProgramBuilder builder, MockPdb pdb) throws Exception {
		Program program = builder.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		for (DataType type : getRegularTypes(dtm)) {
			pdb.addType(type);
		}
		for (CppCompositeType cppType : getCppTypes(dtm)) {
			pdb.addType(cppType);
		}
	}

	private void addFunctionInfo(ProgramBuilder builder, MockPdb pdb) throws Exception {
		for (AddressNameBytes funcInfo : functionInfo) {
			builder.setBytes(funcInfo.addr(), funcInfo.bytes());
			pdb.addSymbol(builder.addr(funcInfo.addr()), funcInfo.name());
		}
	}

}
