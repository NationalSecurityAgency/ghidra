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
package ghidra.program.database;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;

import java.nio.charset.StandardCharsets;
import java.util.Date;

class MergeProgramGenerator_Notepads implements MergeProgramGenerator {

	// this is to detect source code changes that could break our brittle setup
	/**
	 * We keep track of this to know if there are any changes in static initialization.  We want
	 * to make sure that all program building runs result in the same ID sequences.  The first
	 * program built triggers static loading, which will cause the IDs for that run to be 
	 * larger than the subsequent runs.  So, we call all known static initializers before we 
	 * run.  This variable lets us know if a new initializer was added, as the ID value between
	 * the first run and the second run will be different.
	 */
	private UniversalID lastGeneratedUniversalID;

	private Object consumer;

	MergeProgramGenerator_Notepads(Object consumer) {
		this.consumer = consumer;
	}

	@Override
	public ProgramDB generateProgram(String programName) throws Exception {

		if ("NotepadMergeListingTest".equals(programName)) {
			return buildNotepadMergeListingTestProgram();
		}
		else if ("NotepadMergeListingTest_X86".equals(programName)) {
			return buildNotepadMergeListingTest_X86Program();
		}
		else if ("notepad".equals(programName)) {
			return buildNotepadProgram();
		}
		else if ("notepad.exe_3.1_w_DotDotDot".equals(programName)) {
			return buildNotepadDotDotDotProgram();
		}
		else if ("notepad2".equals(programName)) {
			return buildNotepadProgram();
		}
		else if ("notepad3".equals(programName)) {
			return buildNotepadProgram3();
		}
		else if ("notepad4".equals(programName)) {
			return buildNotepadProgram();
		}
		throw new AssertException("Add new builder for program: " + programName);
	}

	private ProgramDB buildNotepadEmpty() throws Exception {
		initializeStaticUniversalIDUsage();

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true, consumer);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		return builder.getProgram();
	}

	private ProgramDB buildNotepadProgram3() throws Exception {
		initializeStaticUniversalIDUsage();

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true, consumer);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		return filloutSharedNotepadProgram(builder);
	}

	private ProgramDB buildNotepadProgram() throws Exception {
		initializeStaticUniversalIDUsage();

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true, consumer);

		builder.createMemory(".text", "0x1001000", 0x6600, "comment (1)");
		builder.createMemory(".data", "0x1008000", 0x600, "comment (1)");
		builder.createMemory(".data", "0x1008600", 0x1344, "comment (1)");
		builder.createMemory(".rsrc", "0x100a000", 0x5400, "comment (1)");
		builder.createMemory(".bound_import_table", "0xf00002ef", 0xa8, "Bound Import Table Data");
		builder.createMemory(".debug_data", "0xf000131b", 0x1c, "Debug Data");

		return filloutSharedNotepadProgram(builder);
	}

	private ProgramDB buildNotepadDotDotDotProgram() throws Exception {
		initializeStaticUniversalIDUsage();

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true, consumer);

		builder.createMemory(".text", "0x1001000", 0x6600, "comment (1)");
		builder.createMemory(".data", "0x1008000", 0x600, "comment (1)");
		builder.createMemory(".data", "0x1008600", 0x1344, "comment (1)");
		builder.createMemory(".rsrc", "0x100a000", 0x5400, "comment (1)");

		DataType dt = new Undefined4DataType();
		ParameterImpl p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction(null, "100194b", 20, null, p, p);
		builder.createEmptyFunction(null, "100299e", 20, null, p, p, p);
		builder.createEmptyFunction(null, "1004068", 20, null, true, false, false, p);
		builder.createEmptyFunction(null, "10058b8", 20, null, true, false, false, p, p, p, p, p);
		builder.createEmptyFunction(null, "1004c1d", 20, null, true, true, true, p, p);
		builder.createEmptyFunction(null, "1004132", 20, null, false, true, false, p, p, p);
		builder.createEmptyFunction(null, "10018cf", 20, null, true, false, false);
		builder.createEmptyFunction(null, "100476b", 20, null, false, true, true, p);
		builder.createEmptyFunction(null, "10041fc", 20, null, false, false, true, p);
		builder.createEmptyFunction(null, "1004bc0", 20, null, false, false, true, p);
		builder.createEmptyFunction(null, "1004a15", 20, null, false, true, false, p, p);

		return filloutSharedNotepadProgram(builder);
	}

	private ProgramDB filloutSharedNotepadProgram(ToyProgramBuilder builder) throws Exception {

		// functions
		Function function =
			builder.createEmptyFunction("entry", "0x1006420", 396, new Undefined1DataType());

		// structures
		Structure intStruct = new StructureDataType("IntStruct", 0);
		intStruct.add(new ByteDataType(), "field0", "");
		intStruct.add(new WordDataType());
		intStruct.add(new DWordDataType());
		intStruct.add(new QWordDataType());
		intStruct.setCategoryPath(new CategoryPath("/Category1/Category2/Category3"));

		builder.addDataType(intStruct);

		Structure dllTable = new StructureDataType("DLL_Table", 0);
		dllTable.add(new StringDataType(), 13, "COMDLG32", "");
		dllTable.add(new StringDataType(), 12, "SHELL32", "");
		dllTable.add(new StringDataType(), 11, "MSVCRT", "");
		dllTable.add(new StringDataType(), 13, "ADVAPI32", "");
		dllTable.add(new StringDataType(), 13, "KERNEL32", "");
		dllTable.add(new StringDataType(), 10, "GDI32", "");
		dllTable.add(new StringDataType(), 11, "USER32", "");
		dllTable.add(new StringDataType(), 13, "WINSPOOL32", "");

		builder.addDataType(dllTable);

		Union union = new UnionDataType("CoolUnion");
		union.add(new QWordDataType());
		union.add(new WordDataType());

		// Undefined * * * * *
		union.add(createPointer(DataType.DEFAULT, 5));
		union.add(dllTable);
		PointerDataType pointer = new PointerDataType(dllTable, 4);
		union.add(pointer);
		union.setCategoryPath(new CategoryPath("/Category1/Category2"));

		builder.addDataType(union);

		Structure charStruct = new StructureDataType("CharStruct", 0);
		charStruct.add(new CharDataType());
		charStruct.add(new StringDataType(), 4);
		charStruct.add(new TerminatedStringDataType(), 8);
		charStruct.add(new UnicodeDataType(), 12);
		charStruct.setCategoryPath(new CategoryPath("/Category1/Category2/Category4"));

		builder.addDataType(charStruct);

		Structure struct = new StructureDataType("ArrayStruct", 0);
		pointer = createPointer(intStruct, 2);
		struct.add(new ArrayDataType(pointer, 10, pointer.getLength()));
		struct.add(new ArrayDataType(intStruct, 3, intStruct.getLength()));
		struct.add(createPointer(DataType.DEFAULT, 5));
		struct.setCategoryPath(new CategoryPath("/MISC"));

		builder.addDataType(struct);

		Structure floatStruct = new StructureDataType("FloatStruct", 0);
		floatStruct.add(new FloatDataType());
		floatStruct.add(new DoubleDataType());
		floatStruct.setCategoryPath(new CategoryPath("/Category1/Category2/Category5"));

		builder.addDataType(struct);

		EnumDataType enumm = new EnumDataType("FavoriteColors", 1);
		enumm.add("Red", 0x0);
		enumm.add("Violet", 0x1);
		enumm.add("Black", 0x2);
		enumm.add("Pink", 0x3);
		enumm.setCategoryPath(new CategoryPath("/MISC"));

		builder.addDataType(enumm);

		//
		// From notepad2		
		//
		// functions
		FunctionDefinitionDataType def = new FunctionDefinitionDataType("MyFunctionDef");
		def.setReturnType(dllTable);

		ParameterDefinition[] params = new ParameterDefinition[4];
		params[0] = new ParameterDefinitionImpl("param_4", new WordDataType(), "");
		params[1] = new ParameterDefinitionImpl("param_8", new CharDataType(), "");
		params[2] = new ParameterDefinitionImpl("param_c", new Undefined4DataType(), "");
		params[3] = new ParameterDefinitionImpl("param_10", new Undefined4DataType(), "");
		def.setArguments(params);

		def.setCategoryPath(new CategoryPath("/MISC"));

		builder.addDataType(def);

		// datatypes
		Structure bar = new StructureDataType("Bar", 0);
		bar.add(new WordDataType());
		bar.setCategoryPath(new CategoryPath("/MISC"));

		Structure foo = new StructureDataType("Foo", 0);
		foo.add(new ByteDataType());
		foo.add(new ByteDataType());
		foo.add(new WordDataType());
		foo.setCategoryPath(new CategoryPath("/MISC"));

		Structure struct1 = new StructureDataType("Structure_1", 0);
		struct1.add(new ByteDataType());
		struct1.add(new WordDataType());
		struct1.add(new ByteDataType());
		struct1.setCategoryPath(new CategoryPath("/Category1/Category2"));

		foo.add(bar);
		bar.add(new PointerDataType(struct1, 4));
		struct1.insert(2, foo);

		builder.addDataType(bar);
		builder.addDataType(foo);
		builder.addDataType(struct1);

		TypedefDataType td = new TypedefDataType("FooTypedef", foo);
		td.setCategoryPath(new CategoryPath("/MISC"));
		builder.addDataType(td);

		enumm = new EnumDataType("ExpressionType", 1);
		enumm.add("TYPE_INT", 0x0);
		enumm.add("TYPE_FLOAT", 0x1);
		enumm.add("TYPE_RELOC", 0x2);
		enumm.add("TYPE_STRING", 0x3);
		enumm.add("TYPE_BITS", 0x4);
		enumm.add("TYPE_UNKNOWN", 0x5);
		enumm.setCategoryPath(new CategoryPath("/MISC"));

		builder.addDataType(enumm);

		Structure myStruct = new StructureDataType("MyStruct", 0);
		pointer = createPointer(intStruct, 2);
		myStruct.add(new ArrayDataType(floatStruct, 10, pointer.getLength()));
		pointer = createPointer(charStruct, 3);
		myStruct.add(new ArrayDataType(intStruct, 3, intStruct.getLength()));
		myStruct.add(pointer);
		myStruct.setCategoryPath(new CategoryPath("/Category1/Category2"));

		builder.addDataType(myStruct);

		//
		// notepad4
		//
		builder.addCategory(new CategoryPath("/A"));
		builder.addCategory(new CategoryPath("/A/B"));
		builder.addCategory(new CategoryPath("/A/C"));

		// program trees
		builder.createProgramTree("Main Tree");
		builder.getOrCreateModule("Main Tree", "Strings");
		builder.createProgramTree("Tree Three");
		builder.getOrCreateModule("Tree Three", "B");
		builder.createProgramTree("Tree Two");
		builder.createProgramTree("Tree One");

		// code units
		builder.addBytesFallthrough("0x100652a");
		builder.disassemble("0x100652a", 1);

		//
		//
		//
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent
		ProgramDB program = builder.getProgram();
		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.TRUE);

		UniversalID ID = UniversalIdGenerator.nextID();

		if (lastGeneratedUniversalID != null) {
			if (!lastGeneratedUniversalID.equals(ID)) {
				// if this happens, update initializeStaticUniversalIDUsage()
				throw new AssertException("Expected Test UniversalID has changed.  "
					+ "This is probably due to an new static usage of the UniversalIDGenerator.");
			}
		}

		return program;
	}

	private void initializeStaticUniversalIDUsage() {
		DataType dt = DataType.DEFAULT;
	}

	private PointerDataType createPointer(DataType dt, int levels) {
		PointerDataType pointer = new PointerDataType(dt);
		for (int i = 0; i < levels - 1; i++) {
			pointer = new PointerDataType(pointer);
		}
		return pointer;
	}

	private ProgramDB buildNotepadMergeListingTest_X86Program() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("buildNotepadMergeListingTest_X86Program", ProgramBuilder._X86,
				consumer);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		builder.createNamespace("FirstNamespace");
		builder.createNamespace("SecondNamespace");
		builder.createNamespace("EmptyNamespace");
		builder.createNamespace("SubNamespace", "SecondNamespace", SourceType.USER_DEFINED);

		builder.createLabel("0x100e483", "AAA");

		Function function =
			builder.createEmptyFunction("FUN_100248f", "0x100248f", 1214, new Undefined1DataType());

		String namespace = function.getName();
		builder.createLabel("0x1002691", "AAA", namespace);

		DataType dt = new Undefined4DataType();
		function = builder.createEmptyFunction("entry", "0x1006420", 396, new Undefined1DataType());
		namespace = function.getName();
		builder.createLocalVariable(function, "local_1", dt, -0x6c);
		builder.createLocalVariable(function, "local_2", dt, -0x68);
		builder.createLocalVariable(function, "local_3", dt, -0x70);

		builder.createLabel("0x1006420", "ABC", namespace);

		function =
			builder.createEmptyFunction("FUN_10033f6", "0x10033f6", 87, new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x1003439", "BBB", namespace);

		builder.createLabel("0x10044d0", "DDD");
		builder.createLabel("0x1006420", "DEF");

		function =
			builder.createEmptyFunction("FUN_1004444", "0x1004444", 652, new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x10044d0", "DDD6");

		builder.createLabel("0x1004bdc", "EEE");

		function =
			builder.createEmptyFunction("FUN_1004bc0", "FirstNamespace", "0x1004bc0", 93,
				new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x1004bdc", "EE4", namespace);

		builder.createLabel("0x1003075", "QQQ"); // Instruction Label?
		builder.createLabel("0x1002721", "XXX");
		builder.createLabel("0x1003075", "YYY");
		builder.createLabel("0x1003075", "ZZZ");

		// bookmarks
		builder.createBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");
		builder.createBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");
		builder.createBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");
		builder.createBookmark("0x1002f01", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");

		//
		//
		//
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		ParameterImpl p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction(null, "1002c93", 20, null, p, p, p);
		Function fun = builder.createEmptyFunction(null, "100415a", 20, null, p, p, p);
		builder.createLocalVariable(fun, "local_1", dt, -8);
		builder.createLocalVariable(fun, "local_2", dt, -12);
		builder.createLocalVariable(fun, "local_3", dt, -16);

		fun = builder.createEmptyFunction(null, "1002a91", 20, null, p);
		builder.createLocalVariable(fun, "local_1", dt, -8);
		builder.createLocalVariable(fun, "local_2", dt, -12);
		builder.createLocalVariable(fun, "local_3", dt, -16);

		fun = builder.createEmptyFunction(null, "1002b44", 20, null, p);
		builder.createLocalVariable(fun, "local_1", dt, -8);

		fun = builder.createEmptyFunction(null, "1003ac0", 20, null, p, p, p, p);
		builder.createLocalVariable(fun, "local_1", dt, -8);
		builder.createLocalVariable(fun, "local_2", dt, -12);

		fun = builder.createEmptyFunction(null, "1004c1d", 20, null, p, p);
		builder.createLocalVariable(fun, "local_1", dt, -8);
		builder.createLocalVariable(fun, "local_2", dt, -12);

		builder.createEmptyFunction(null, "0x10021f3", 10, null);
		builder.createEmptyFunction(null, "0x1001ae3", 1721, null);

		fun = builder.createEmptyFunction(null, "SecondNamespace", "0x1002239", 10, null, p);
		builder.createLocalVariable(fun, "local_1", dt, -8);

		fun =
			builder.createEmptyFunction("FUN_1003bed", "0x1003bed", 783, new Undefined1DataType(),
				p);
		namespace = fun.getName();
		builder.createLabel("0x1003e25", "CCC", namespace);
		builder.applyDataType("0x1001004", new Pointer32DataType(), 4);
		builder.setBytes("100642f", "64 a1 a0 00 00 00 50 64 89 25 00 00 00", true);

		// RefMergeRegTest
		builder.createEmptyFunction(null, "10018a0", 47, null);
		builder.createRegisterReference("10018a6", "ESI", 0);

		builder.createEmptyFunction(null, "1002cf5", 40, null);
		builder.setBytes("1002d0b", "8b f8", true);
		builder.createRegisterReference("1002d0b", "EDI", 0);
		builder.createRegisterReference("1002d0b", "EAX", 1);
		builder.setBytes("1002d18", "8d 44 00 02", true);

		builder.createEmptyFunction(null, "1002950", 40, null);

		builder.setBytes("100295a", "66 85 c9", true);
		builder.createRegisterReference("100295a", "CX", 1);

//		builder.createEmptyFunction(null, "10033f6", 40, null);
		builder.createRegisterReference("10033fe", "EDI", 0);

		builder.createStackReference("1001af5", RefType.READ, -0x24c, SourceType.USER_DEFINED, 0);
		builder.setBytes("1001aec", "66 a1 98 33 00 01", true);
		builder.setBytes("1001b03", "8d bd ba fd ff ff", true);
		builder.createStackReference("1001b03", RefType.READ, -0x24a, SourceType.DEFAULT, 1);

		builder.createStackReference("1002125", RefType.READ, -0x10, SourceType.USER_DEFINED, 0);

		builder.createClassNamespace("MyClass", null, SourceType.USER_DEFINED);

		builder.createEmptyFunction(null, "MyClass", CompilerSpec.CALLING_CONVENTION_thiscall,
			"0x1002249", 10, IntegerDataType.dataType, IntegerDataType.dataType);
		builder.createLocalVariable(fun, "local_1", dt, -8);

		ProgramDB program = builder.getProgram();

		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.TRUE);

		UniversalID ID = UniversalIdGenerator.nextID();

		if (lastGeneratedUniversalID != null) {
			if (!lastGeneratedUniversalID.equals(ID)) {
				// if this happens, update initializeStaticUniversalIDUsage()
				throw new AssertException("Expected Test UniversalID has changed.  "
					+ "This is probably due to an new static usage of the UniversalIDGenerator.");
			}
		}

		return program;
	}

	private ProgramDB buildNotepadMergeListingTestProgram() throws Exception {

		ToyProgramBuilder builder =
			new ToyProgramBuilder("NotepadMergeListingTest", true, consumer);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		builder.createNamespace("FirstNamespace");
		builder.createNamespace("SecondNamespace");
		builder.createNamespace("EmptyNamespace");
		builder.createNamespace("SubNamespace", "SecondNamespace", SourceType.USER_DEFINED);

		builder.createLabel("0x100e483", "AAA");

		Function function =
			builder.createEmptyFunction("FUN_100248f", "0x100248f", 1214, new Undefined1DataType());

		String namespace = function.getName();
		builder.createLabel("0x1002691", "AAA", namespace);

		function = builder.createEmptyFunction("entry", "0x1006420", 396, new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x1006420", "ABC", namespace);

		function =
			builder.createEmptyFunction("FUN_10033f6", "0x10033f6", 87, new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x1003439", "BBB", namespace);

		function =
			builder.createEmptyFunction("FUN_1003bed", "0x1003bed", 783, new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x1003e25", "CCC", namespace);

		builder.createLabel("0x10044d0", "DDD");
		builder.createLabel("0x1006420", "DEF");

		function =
			builder.createEmptyFunction("FUN_1004444", "0x1004444", 652, new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x10044d0", "DDD6", "FUN_01004444");

		function =
			builder.createEmptyFunction("FUN_1004bc0", "FirstNamespace", "0x1004bc0", 93,
				new Undefined1DataType());
		namespace = function.getName();
		builder.createLabel("0x1004bdc", "EEE4", namespace);
		builder.createLabel("0x1004bdc", "EEE");

		builder.createLabel("0x1003075", "YYY");
		builder.createLabel("0x1003075", "QQQ"); // Instruction Label?
		builder.createLabel("0x1002721", "XXX");
		builder.createLabel("0x1003075", "ZZZ");

		// bookmarks
		builder.createBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");
		builder.createBookmark("0x100248f", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");
		builder.createBookmark("0x1001978", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");
		builder.createBookmark("0x1002f01", BookmarkType.ANALYSIS, "Found Code",
			"Found code from operand reference");

		// equates (note we need instructions where there are equates for the merger to work)
		builder.addBytesMoveImmediate("0x1001d0b", (byte) 1);
		builder.disassemble("0x1001d0b", 1);
		builder.createEquate("0x1001d0b", "01", 1, 1);

		builder.addBytesMoveImmediate("0x1001da6", (byte) 1);
		builder.disassemble("0x1001da6", 1);
		builder.createEquate("0x1001da6", "1", 1, 1);

		builder.addBytesMoveImmediate("0x1001cea", (byte) 1);
		builder.disassemble("0x1001cea", 1);
		builder.createEquate("0x1001cea", "ein", 1, 1);

		builder.addBytesMoveImmediate("0x10019a4", (byte) 0);
		builder.disassemble("0x10019a4", 1);
		builder.createEquate("0x10019a4", "nothing", 0, 1);

		builder.addBytesMoveImmediate("0x1001b5d", (byte) 1);
		builder.disassemble("0x1001b5d", 1);
		builder.createEquate("0x1001b5d", "one", 1, 1);

		builder.addBytesMoveImmediate("0x1001dd8", (byte) 3);
		builder.disassemble("0x1001dd8", 1);
		builder.createEquate("0x1001dd8", "tres", 3, 1);

		builder.addBytesMoveImmediate("0x1001bc9", (byte) 1);
		builder.disassemble("0x1001bc9", 1);
		builder.createEquate("0x1001bc9", "uno", 1, 1);

		builder.addBytesMoveImmediate("0x10019a2", (byte) 0);
		builder.disassemble("0x10019a2", 1);
		builder.createEquate("0x10019a2", "zero", 0, 1);

		builder.addBytesMoveImmediate("0x10019f8", (byte) 0);
		builder.disassemble("0x10019f8", 1);
		builder.createEquate("0x10019f8", "zero", 0, 1);

		// equate references
		builder.addBytesMoveImmediate("0x1002d18", (byte) 1);
		builder.disassemble("0x1002d18", 1);

		builder.addBytesMoveImmediate("0x1002533", (byte) 1);
		builder.disassemble("0x1002533", 1);

		// code units
		builder.addBytesNOP("0x1001bbd", 6);
		builder.disassemble("0x1001bbd", 1);

		builder.addBytesNOP("0x1001c2b", 9);
		builder.disassemble("0x1001c2b", 1);

		builder.addBytesFallthroughSetNoFlowContext("0x1004ab5", 0);
		builder.disassemble("0x1004ab5", 1);
		builder.addBytesNOP("0x1004aa5", 6);
		builder.disassemble("0x1004aa5", 16);
		builder.addBytesFallthrough("0x1004adb");
		builder.disassemble("0x1004adb", 1);
		builder.addBytesNOP("0x1004b19", 6);
		builder.disassemble("0x1004b19", 1);

		builder.addBytesFallthrough("0x10024ea");
		builder.disassemble("0x10024ea", 1);
		builder.addBytesFallthrough("0x01002f49");
		builder.disassemble("0x01002f49", 1);
		builder.addBytesFallthrough("0x01002f38");
		builder.disassemble("0x01002f38", 1);
		builder.addBytesFallthrough("0x01002ff6");
		builder.disassemble("0x01002ff6", 1);
		builder.addBytesFallthrough("0x01003059");
		builder.disassemble("0x01003059", 1);
		builder.addBytesFallthrough("0x1002f5d");
		builder.disassemble("0x1002f5d", 1);
		builder.addBytesFallthrough("0x01003105");
		builder.disassemble("0x01003105", 1);
		builder.addBytesFallthrough("0x0100319a");
		builder.disassemble("0x0100319a", 1);

		builder.addBytesFallthrough("0x1001a92");
		builder.disassemble("0x1001a92", 1);
		builder.addBytesFallthrough("0x1001abb");
		builder.disassemble("0x1001abb", 1);
		builder.addBytesFallthrough("0x1001aec");
		builder.disassemble("0x1001aec", 1);
		builder.addBytesFallthrough("0x1002eaf");
		builder.disassemble("0x1002eaf", 1);
		builder.addBytesFallthrough("0x1002f3e");
		builder.disassemble("0x1002f3e", 1);
		builder.addBytesFallthrough("0x1002f73");
		builder.disassemble("0x1002f73", 1);
		builder.addBytesFallthrough("0x01006421");
		builder.disassemble("0x01006421", 1);
		builder.addBytesNOP("0x0100642f", 6);
		builder.disassemble("0x0100642f", 1);
		builder.setFallthrough("0x0100642f", "0x01006435");
		builder.addBytesFallthrough("0x01006443");
		builder.disassemble("0x01006443", 1);
		builder.setFallthrough("0x01006443", "0x01006446");

		builder.applyDataType("0x100a2c5", new WordDataType(), 1);
		builder.createEncodedString("0x100a2d8", "hi", StandardCharsets.US_ASCII, false);
		builder.applyDataType("0x100a2f4", new DWordDataType(), 1);
		builder.applyDataType("0x1006654", new DWordDataType(), 1);
		builder.applyDataType("0x1006674", new DWordDataType(), 1);
		builder.applyDataType("0x1006be2", new WordDataType(), 1);
		builder.applyDataType("0x1007446", new WordDataType(), 1);

		// data types
		Structure myStruct = new StructureDataType("ThreeBytes", 0);
		myStruct.add(new ByteDataType());
		myStruct.add(new ByteDataType());
		myStruct.add(new ByteDataType());
		builder.addDataType(myStruct);

		Union union = new UnionDataType("UnionSize4");
		union.add(new ByteDataType());
		union.add(new WordDataType());
		union.add(new DWordDataType());
		union.add(new Pointer32DataType());
		builder.addDataType(union);

		// references
		builder.createMemoryReadReference("0x1001a92", "0x1001370");
		builder.createMemoryReadReference("0x1001abb", "0x1001ac1");
		builder.createMemoryReference("0x1001aec", "0x1001398", RefType.READ,
			SourceType.USER_DEFINED, 1);
		builder.createMemoryReadReference("0x1002eaf", "0x1002ee2");

		//
		//
		//
		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		builder.createExternalLibraries("ADVAPI32.DLL", "COMDLG32.DLL", "GDI32.DLL",
			"KERNEL32.DLL", "MSVCRT.DLL", "SHELL32.DLL", "USER32.DLL", "WINSPOOL.DRV");
		builder.bindExternalLibrary("ADVAPI32.DLL", "//advapi32.dll");
		builder.bindExternalLibrary("USER32.DLL", "//user32.dll");

		builder.createExternalReference("0x1001000", "ADVAPI32.DLL", "IsTextUnicode", 0);
		builder.createExternalReference("0x1001004", "ADVAPI32.DLL", "RegCreateKeyW", 0);
		builder.createExternalReference("0x1001008", "ADVAPI32.DLL", "RegQueryValueExW", 0);
		builder.createExternalReference("0x1001010", "ADVAPI32.DLL", "RegOpenKeyExA", "77db82ac", 0);
		builder.createExternalReference("0x10010C0", "ADVAPI32.DLL", "WhatEver", 0);
		builder.createExternalReference("0x10011e4", "USER32.DLL", "setCursor", 0);

		builder.createEmptyFunction(null, "0x1002950", 78, null);
		builder.createEmptyFunction(null, "0x1002cf5", 121, null);
		builder.createEmptyFunction(null, "0x1002b7d", 278, null);
		builder.createEmptyFunction(null, "0x10031ee", 98, null);
		builder.createEmptyFunction(null, "0x1002a91", 179, null);
		builder.createEmptyFunction(null, "0x1002b44", 57, null);
		builder.createEmptyFunction(null, "0x1002c93", 98, null);
		builder.createEmptyFunction(null, "FirstNamespace", "0x100194b", 45, null);
		builder.createEmptyFunction(null, "0x1001ae3", 1721, null);
		builder.createEmptyFunction(null, "0x1003250", 133, null);
		builder.createEmptyFunction(null, "0x10059a3", 716, null);
		builder.createLabel("1001000", "ADVAPI32.DLL::IsTextUnicode");

		// SymbolMergeManager2Test
		builder.createLabel("10044d0", "DDD");

		DataType dt = new Undefined4DataType();
		ParameterImpl p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction(null, "1004132", 20, null, p);
		builder.createEmptyFunction(null, "1004c1d", 20, null, p, p);

		builder.createMemoryCallReference("1002950", "0x100194b"); // thunk merge tests
		builder.createMemoryCallReference("1002cf5", "0x1004132"); // thunk merge tests
		builder.createMemoryCallReference("1002b7d", "0x1004c1d"); // thunk merge tests

		builder.createFunction("0x0100219c");	// symbolMergeManagerFunctionSourceTest
		builder.createEmptyFunction(null, "100415a", 20, null, p, p, p);

		builder.createClassNamespace("EmptyClass", null, SourceType.ANALYSIS);

		builder.createClassNamespace("FirstClass", null, SourceType.ANALYSIS);
		builder.createEmptyFunction(null, "FirstClass", "1005887", 20, null);
		builder.createEmptyFunction(null, "FirstClass", "10058b8", 20, null);
		builder.createEmptyFunction(null, "SecondNamespace", "0x1002239", 10, null);

		ProgramDB program = builder.getProgram();

		AbstractGenericTest.setInstanceField("recordChanges", program, Boolean.TRUE);

		UniversalID ID = UniversalIdGenerator.nextID();

		if (lastGeneratedUniversalID != null) {
			if (!lastGeneratedUniversalID.equals(ID)) {
				// if this happens, update initializeStaticUniversalIDUsage()
				throw new AssertException("Expected Test UniversalID has changed.  "
					+ "This is probably due to an new static usage of the UniversalIDGenerator.");
			}
		}

		return program;
	}
}
