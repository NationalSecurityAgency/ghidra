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
package ghidra.test;

import generic.test.TestUtils;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ClassicSampleX86ProgramBuilder extends ProgramBuilder {

	private boolean disableAnalysis;

	/**
	 * Construct sample program builder using the x86 language and default compiler spec.
	 * A set of predefined memory bytes, code units and functions will be added.
	 * This builder object will be the program consumer and must be disposed to properly
	 * release the program.
	 * 
	 * @throws Exception if an unexpected exception happens
	 */
	public ClassicSampleX86ProgramBuilder() throws Exception {
		this(false);
	}

	/**
	 * Construct sample program builder using the x86 language and default compiler spec.
	 * A set of predefined memory bytes, code units and functions will be added.
	 * This builder object will be the program consumer and must be disposed to properly
	 * release the program.
	 * 
	 * @param disableAnalysis if true, the analysis manager will be disabled
	 * @throws Exception if an unexpected exception happens
	 */
	public ClassicSampleX86ProgramBuilder(boolean disableAnalysis) throws Exception {
		this("sample", disableAnalysis, null);
	}

	/**
	 * Construct sample program builder using the x86 language and default compiler spec.
	 * A set of predefined memory bytes, code units and functions will be added.
	 * This builder object will be the program consumer and must be disposed to properly
	 * release the program.
	 * @param name program name
	 * 
	 * @param disableAnalysis if true, the analysis manager will be disabled
	 * @throws Exception if an unexpected exception happens
	 */
	public ClassicSampleX86ProgramBuilder(String name, boolean disableAnalysis) throws Exception {
		this(name, disableAnalysis, null);
	}

	/**
	 * Construct sample program builder using the x86 language and default compiler spec.
	 * A set of predefined memory bytes, code units and functions will be added.
	 * @param name program name
	 * @param disableAnalysis if true, the analysis manager will be disabled
	 * @param consumer program consumer (if null this builder will be used as consumer and must be disposed to release program)
	 * @throws Exception
	 */
	public ClassicSampleX86ProgramBuilder(String name, boolean disableAnalysis, Object consumer)
			throws Exception {
		super(name, ProgramBuilder._X86, consumer);

		setupSampleProgram(disableAnalysis);
	}

	private void setupSampleProgram(boolean disableAnalysis) throws Exception {
		this.disableAnalysis = disableAnalysis;
		Program p = getProgram();
		if (disableAnalysis) {
			AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(p);
			TestUtils.setInstanceField("isEnabled", analysisMgr, Boolean.FALSE);
		}
		else {
			// enable stack analysis
			startTransaction();
			p.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("Stack", true);
			endTransaction();
		}

		createMemory(".text", "0x01001000", 0x6600);
		createMemory(".text", "0x01008000", 0x600);
		createMemory(".text", "0x0100a000", 0x5400);
		createMemory(".text", "0xf0000248", 0xa8);
		createMemory(".text", "0xf0001300", 0x1c);

		//
		// Externals
		//
		setBytes("0x01001000", "85 4f dc 77");
		applyDataType("0x01001000", new Pointer32DataType(), 1);
		createLabel("0x01001000", "ADVAPI32.dll_IsTextUnicode");
		createExternalReference("0x01001000", "ADVAPI32.dll", "IsTextUnicode", 0);
		createMemoryReference("0x010063cc", "0x01001000", RefType.INDIRECTION, SourceType.DEFAULT);

		setBytes("0x01001004", "b0 90 db 77");
		applyDataType("0x01001004", new Pointer32DataType(), 1);
		createLabel("0x01001004", "ADVAPI32.dll_RegCreateKeyW");
		createExternalReference("0x01001004", "ADVAPI32.dll", "RegCreateKeyW", 0);

		setBytes("0x01001008", "9c 1d b4 76");
		applyDataType("0x01001008", new Pointer32DataType(), 1);
		createLabel("0x01001008", "ADVAPI32.dll_RegQueryValueExW");
		createExternalReference("0x01001008", "ADVAPI32.dll", "RegQueryValueExW", 0);

		setBytes("0x010012f4", "9c 1d b4 76");
		applyDataType("0x010012f4", new Pointer32DataType(), 1);
		createLabel("0x010012f4", "comdlg32.dll_CommDlgExtendedError");
		createExternalReference("0x010012f4", "comdlg32.dll", "CommDlgExtendedError", 0);
		createMemoryReference("0x010030d2", "0x010012f4", RefType.INDIRECTION, SourceType.DEFAULT);

		//
		// Functions
		//
		// create the entry function, complete with bytes and disassembly
		createFunction_entry();

		createFunction_sscanf();

		createFunction_248f();

		createFunction_2cf5();

		createFunction_48a3();

		createFunction_59a3();

		createFunction_30d2();

		createFunction_2239();

		//
		// Labels
		//		
		createLabel("0x01001160", "MSVCRT.dll___set_app_type");
		createLabel("0x01002d1f", "MyLocal");
		createLabel("0x01002d2b", "AnotherLocal");
		createLabel("0x0100eb90", "rsrc_String_4_5c8");
		createLabel("0x0100f1d0", "rsrc_String_6_64");

		//
		// Equates
		//
		createEquate("0x100644d", "TWO", 0x2, 0);
		setBytes("0x0100f204", "65 00 6e 00 64 00 69 00"); // prepare for setting of an equate
		applyDataType("0x0100f204", new QWordDataType(), 1);

		//
		// Bytes for Data
		//
		// string data
		setBytes("0x0100750e", "52 65 67 69 73 74 65 72 43 6c 61 73 73 45 78 57 00");
		setBytes("0x01001484",
			"69 00 57 00 69 00 6e 00 64 00 6f 00 77 00 50 00 6f 00 73 00 44 00 58 00");
		setBytes("0x01006a02", "43 68 6f 6f 73 65 46 6f 6e 74 57 00"); // ChooseFontW
		setBytes("0x01006a0e", "15 00");
		setBytes("0x01006a10", "52 65 70 6c 61 63 65 54 65 78 74 57 00"); // ReplaceTextW
		setBytes("0x01006a1e", "04 00");
		setBytes("0x01008014", "01 00 00 00 53 00 61 00 6d 00 70 00 6c 00 65 00");
		setBytes("0x010085a7", "00 ef bb bf"); // float
		setBytes("0x010085a9", "bb bf 00 ff fe 00 00 fe"); // double		

		//
		// Data Types
		//
		addDataType(new ByteDataType());
		addDataType(new DWordDataType());

		StructureDataType floatStruct = new StructureDataType("FloatStruct", 0);
		floatStruct.add(new FloatDataType());
		addDataType(floatStruct);

		StructureDataType charStruct = new StructureDataType("CharStruct", 0);
		charStruct.add(new CharDataType());
		charStruct.add(new StringDataType(), 4);
		charStruct.add(new TerminatedStringDataType(), 8);
		charStruct.add(new UnicodeDataType(), 12);
		addDataType(charStruct);

		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(floatStruct);
		Pointer32DataType pointer = new Pointer32DataType(charStruct);
		pointer = new Pointer32DataType(pointer);
		pointer = new Pointer32DataType(pointer);
		myStruct.add(pointer);
		addDataType(myStruct);

		StructureDataType dllTable = new StructureDataType("DLL_Table", 0);
		dllTable.add(new StringDataType(), 13, "COMDLG32", "");
		dllTable.add(new StringDataType(), 12, "SHELL32", "");
		dllTable.add(new StringDataType(), 11, "MSVCRT", "");
		dllTable.add(new StringDataType(), 13, "ADVAPI21", "");
		dllTable.add(new StringDataType(), 13, "KERNEL32", "");
		dllTable.add(new StringDataType(), 10, "GDI32", "");
		dllTable.add(new StringDataType(), 11, "USER32", "");
		dllTable.add(new StringDataType(), 13, "WINSPOOL", "");
		addDataType(dllTable);
		applyDataType("0xf0000290", dllTable);

		UnionDataType coolUnion = new UnionDataType("CoolUnion");
		coolUnion.add(new QWordDataType());
		coolUnion.add(new WordDataType());
		pointer = new Pointer32DataType(DefaultDataType.dataType);
		coolUnion.add(pointer);
		coolUnion.add(dllTable);
		pointer = new Pointer32DataType(dllTable);
		coolUnion.add(pointer);
		applyDataType("0x0100d0f3", coolUnion);

		//
		// Comments
		//
		createComment("0x0100415a", "Repeatable Comment", CodeUnit.REPEATABLE_COMMENT);

		//
		// References
		//
		createMemoryReference("0x01004930", "0x010049f9", RefType.CONDITIONAL_JUMP,
			SourceType.ANALYSIS);

// Any test needing complete analysis should call the analysis method 
//		if (!disableAnalysis) {
//			analyze();
//		}
	}

	private void createFunction_30d2() throws Exception, OverlappingFunctionException {
		setBytes("0x010030d2", "ff 25 f4 12 00 01");

		Function function = createFunction("0x010030d2");
		startTransaction();
		function.setBody(new AddressSet(getProgram(), addr("0x010030d2"), addr("0x010030d7")));
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x010030d2"), addr("0x010030d7")));
	}

	private void createFunction_59a3() throws Exception, OverlappingFunctionException {
		setBytes("0x010059a3",
			"55 8b ec 83 ec 14 53 56 33 f6 57 39 75 10 56 89 75 ec 89 75 f0 89 " +
				"75 fc 68 80 00 00 00 75 1a 6a 03 56 6a 01 68 00 00 00 c0 ff 75 0c ff 15 b4 10 00 01 " +
				"a3 d0 8b 00 01 eb 30 6a 04 56 6a 03 68 00 00 00 c0 ff 75 0c ff 15 b4 10 00 01 83 f8 " +
				"ff a3 d0 8b 00 01 74 13 ff 15 8c 10 00 01 33 c9 3d b7 00 00 00 0f 95 c1 89 4d ec 83 " +
				"3d d0 8b 00 01 ff 75 27 39 75 10 0f 84 e1 01 00 00 6a 30 ff 75 0c ff 35 60 80 00 01 " +
				"ff 35 50 80 00 01 ff 75 08 e8 be d2 ff ff e9 c3 01 00 00 39 35 e4 87 00 01 74 05 e8 " +
				"e5 fe ff ff 8b 3d 14 12 00 01 56 56 6a 0e ff 35 d4 87 00 01 ff d7 56 56 68 bd 00 00 " +
				"00 8b d8 ff 35 d4 87 00 01 ff d7 3b c6 89 45 f4 0f 84 38 01 00 00 50 ff 15 ec 10 00 " +
				"01 3b c6 89 45 10 0f 84 26 01 00 00 a1 cc 8b 00 01 48 0f 84 da 00 00 00 48 0f 84 89 " +
				"00 00 00 48 75 1f 8d 45 f8 56 50 6a 03 68 a8 85 00 01 ff 35 d0 8b 00 01 ff 15 28 11 " +
				"00 01 c7 45 fc e9 fd 00 00 33 c0 83 3d cc 8b 00 01 03 74 0c ff 15 38 11 00 01 89 45 " +
				"fc 8d 45 f0 50 56 56 56 53 ff 75 10 56 ff 75 fc ff 15 14 11 00 01 39 75 f0 8b f8 74 " +
				"22 6a 31 ff 75 0c ff 35 90 80 00 01 ff 35 50 80 00 01 ff 75 08 e8 ee d1 ff ff 83 f8 " +
				"02 0f 84 a7 00 00 00 57 53 ff 75 10 ff 75 fc ff 35 d0 8b 00 01 e8 95 fd ff ff eb 78 " +
				"8b 3d 28 11 00 01 8d 45 f8 56 50 6a 02 68 b0 85 00 01 ff 35 d0 8b 00 01 ff d7 53 ff " +
				"75 10 ff 75 10 e8 3c fd ff ff 8d 45 f8 56 50 8d 04 1b 50 ff 75 10 ff 35 d0 8b 00 01 " +
				"ff d7 53 8b f8 ff 75 10 ff 75 10 e8 1a fd ff ff eb 30 8b 3d 28 11 00 01 8d 45 f8 56 " +
				"50 6a 02 68 ac 85 00 01 ff 35 d0 8b 00 01 ff d7 8d 45 f8 56 50 8d 04 1b 50 ff 75 10 " +
				"ff 35 d0 8b 00 01 ff d7 8b f8 3b fe 75 65 ff 35 40 8f 00 01 ff 15 e4 11 00 01 ff 75 " +
				"0c e8 39 07 00 00 ff 35 40 8f 00 01 ff 15 e4 11 00 01 ff 35 d0 8b 00 01 ff 15 34 11 " +
				"00 01 83 0d d0 8b 00 01 ff 39 75 f4 74 09 ff 75 f4 ff 15 80 10 00 01 39 75 ec 74 09 " +
				"ff 75 0c ff 15 24 11 00 01 39 35 e4 87 00 01 74 05 e8 71 fd ff ff 33 c0 5f 5e 5b c9 " +
				"c2 0c 00 ff 35 d0 8b 00 01 ff 15 10 11 00 01 56 56 68 b9 00 00 00 ff 35 d4 87 00 01 " +
				"ff 15 14 12 00 01 ff 75 0c e8 62 ce ff ff ff 35 d0 8b 00 01 89 35 14 80 00 01 ff 15 " +
				"34 11 00 01 ff 75 f4 83 0d d0 8b 00 01 ff ff 15 80 10 00 01 39 35 e4 87 00 01 74 05 " +
				"e8 12 fd ff ff ff 35 40 8f 00 01 ff 15 e4 11 00 01 6a 01 58 eb 92");

		Function function = createFunction("0x010059a3");
		startTransaction();
		function.setBody(new AddressSet(getProgram(), addr("0x010059a3"), addr("0x01005c6d")));
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x010059a3"), addr("0x01005c6d")));
	}

	private void createFunction_2239() throws Exception, OverlappingFunctionException {
		setBytes("0x01002239",
			"55 8b ec 81 ec 0c 02 00 00 66 a1 98 13 00 01 53 56 57 66 89 85 f4 " +
				"fd ff ff b9 81 00 00 00 33 c0 8d bd f6 fd ff ff f3 ab 6a 01 33 db 39 1d 14 80 00 01 " +
				"5e 66 ab 8b 3d 14 12 00 01 89 75 fc 74 14 53 53 6a 0e ff 35 d4 87 00 01 ff d7 85 c0 " +
				"0f 84 94 00 00 00 53 53 68 b8 00 00 00 ff 35 d4 87 00 01 ff d7 85 c0 0f 84 db 01 00 " +
				"00 39 1d 14 80 00 01 74 0c a1 3c 80 00 01 bf c0 89 00 01 eb 07 bf c0 89 00 01 8b c7 " +
				"8b 4d 08 f7 d9 1b c9 81 e1 00 10 00 00 0f b7 c9 83 c9 33 51 50 ff 35 38 80 00 01 ff " +
				"35 50 80 00 01 ff 35 d0 87 00 01 e8 0a 0a 00 00 83 f8 06 89 45 fc 0f 85 88 01 00 00 " +
				"39 1d 14 80 00 01 74 07 68 9c 13 00 01 eb 23 a1 28 80 00 01 53 57 a3 cc 8b 00 01 ff " +
				"35 d0 87 00 01 e8 86 36 00 00 85 c0 74 07 8b c6 e9 60 01 00 00 57 8d 85 f4 fd ff ff " +
				"50 ff 15 b8 10 00 01 8d 85 f4 fd ff ff bb a8 13 00 01 a3 5c 8c 00 01 a1 84 80 00 01 " +
				"a3 70 8c 00 01 c7 05 74 8c 00 01 66 88 88 00 c7 05 88 8c 00 01 b0 13 00 01 c7 05 84 " +
				"8c 00 01 78 19 00 01 c7 05 4c 8c 00 01 60 88 00 01 89 1d 7c 8c 00 01 89 35 58 8c 00 " +
				"01 89 35 e8 87 00 01 bf 40 8c 00 01 57 e8 4f 0d 00 00 85 c0 0f 84 ae 00 00 00 ff 35 " +
				"5c 8c 00 01 8d 85 f4 fd ff ff 50 ff 15 b8 10 00 01 8d 85 f4 fd ff ff 56 50 ff 35 d0 " +
				"87 00 01 e8 e0 35 00 00 85 c0 75 66 8d 85 f4 fd ff ff 68 c0 89 00 01 50 ff 15 b8 10 " +
				"00 01 8d 85 f4 fd ff ff c7 05 74 8c 00 01 66 88 88 00 a3 5c 8c 00 01 a1 84 80 00 01 " +
				"a3 70 8c 00 01 c7 05 88 8c 00 01 b0 13 00 01 c7 05 84 8c 00 01 78 19 00 01 c7 05 4c " +
				"8c 00 01 60 88 00 01 89 1d 7c 8c 00 01 89 35 58 8c 00 01 89 35 e8 87 00 01 e9 62 ff " +
				"ff ff 8d 85 f4 fd ff ff 50 68 c0 89 00 01 ff 15 b8 10 00 01 a1 cc 8b 00 01 a3 28 80 " +
				"00 01 eb 2d c7 45 fc 02 00 00 00 e8 7b 0c 00 00 85 c0 74 1d 68 10 10 00 00 ff 35 50 " +
				"80 00 01 ff 35 44 80 00 01 ff 35 d0 87 00 01 ff 15 04 12 00 01 83 25 e8 87 00 01 00 " +
				"33 c0 83 7d fc 02 0f 95 c0 5f 5e 5b c9 c2 04 00");

		FunctionManager fm = getProgram().getFunctionManager();
		Function function = null;
		if (disableAnalysis) {
			function = createFunction("0x01002239");
		}
		else {
			// already created due to a reference from another function we've already created
			function = fm.getFunctionAt(addr("0x01002239"));
		}

		startTransaction();
		function.setBody(new AddressSet(getProgram(), addr("0x01002239"), addr("0x0100248c")));
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x01002239"), addr("0x0100248c")), false);

		createMemoryCallReference("0x01002239", "0x01002cf5");
		createMemoryCallReference("0x01002318", "0x010059a3");
	}

	private void createFunction_entry() throws DuplicateNameException, InvalidInputException,
			Exception, OverlappingFunctionException {
		createEntryPoint("0x1006420", "entry");
		setBytes("0x1006420", "55 8b ec 6a ff 68 88 18 00 01 68 d0 65 00 01 64 a1 00 00 00 00 50 " +
			"64 89 25 00 00 00 00 83 c4 98 53 56 57 89 65 e8 c7 45 fc 00 00 00 00 6a 02 ff 15 60 " +
			"11 00 01 83 c4 04 c7 05 38 99 00 01 ff ff ff ff c7 05 3c 99 00 01 ff ff ff ff ff 15 " +
			"5c 11 00 01 8b 0d 44 88 00 01 89 08 ff 15 4c 11 00 01 8b 15 40 88 00 01 89 10 a1 54 " +
			"11 00 01 8b 08 89 0d 40 99 00 01 e8 86 01 00 00 a1 c0 85 00 01 85 c0 75 0e 68 10 66 " +
			"00 01 ff 15 50 11 00 01 83 c4 04 e8 3a 01 00 00 68 0c 80 00 01 68 08 80 00 01 e8 17 " +
			"01 00 00 83 c4 08 8b 15 3c 88 00 01 89 55 94 8d 45 94 50 8b 0d 38 88 00 01 51 8d 55 " +
			"9c 52 8d 45 90 50 8d 4d a0 51 ff 15 48 11 00 01 83 c4 14 68 04 80 00 01 68 00 80 00 " +
			"01 e8 dc 00 00 00 83 c4 08 8b 15 64 11 00 01 8b 32 89 75 8c 80 3e 22 0f 85 a8 00 00 " +
			"00 46 89 75 8c 8a 06 84 c0 74 04 3c 22 75 f2 80 3e 22 75 04 46 89 75 8c 8a 06 84 c0 " +
			"74 0a 3c 20 77 06 46 89 75 8c eb f0 c7 45 d0 00 00 00 00 8d 45 a4 50 ff 15 9c 10 00 " +
			"01 f6 45 d0 01 74 0a 8b 45 d4 25 ff ff 00 00 eb 05 b8 0a 00 00 00 50 56 6a 00 6a 00 " +
			"ff 15 94 10 00 01 50 e8 28 c4 ff ff 89 45 98 50 ff 15 68 11 00 01 eb 83 c4 04 c7 " +
			"45 fc ff ff ff ff 8b 4d f0 64 89 0d 00 00 00 00 5f 5e 5b 8b e5 5d c3 80 3e 20 0f 86 " +
			"66 ff ff ff 46 89 75 8c eb f1");

		Function entry = createFunction("0x1006420");

		startTransaction();
		entry.setBody(new AddressSet(getProgram(), addr("0x1006420"), addr("0x010065aa")));
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x1006420"), addr("0x010065aa")));
	}

	private void createFunction_248f() throws Exception, OverlappingFunctionException {
		setBytes("0x100248f",
			"55 8b ec 53 56 8b 75 0c 57 6a 05 5a 3b f2 77 4b 74 17 8b c6 48 48 0f 85 " +
				"62 02 00 00 6a 00 ff 15 b0 11 00 01 e9 8f 04 00 00 8b 45 10 83 e8 00 74 16 48 74 " +
				"08 48 74 10 e9 7c 04 00 00 ff 75 14 6a 01 52 e9 f4 03 00 00 0f bf 45 16 50 0f bf " +
				"45 14 50 e8 66 f4 ff ff e9 5d 04 00 00 83 fe 10 0f 87 f0 00 00 00 0f 84 82 00 00 " +
				"00 8b c6 83 e8 06 74 33 48 74 14 48 0f 85 03 02 00 00 ff 75 14 ff 75 10 6a 08 e9 " +
				"16 03 00 00 ff 35 d0 87 00 01 ff 15 34 12 00 01 85 c0 0f 85 1c 04 00 00 ff 35 d4 " +
				"87 00 01 eb 3d 66 83 7d 10 01 74 0b 66 83 7d 10 02 0f 85 02 04 00 00 ff 35 d0 87 " +
				"00 01 ff 15 34 12 00 01 85 c0 0f 85 ee 03 00 00 8b 35 30 12 00 01 ff d6 3b 05 d0 " +
				"87 00 01 0f 85 da 03 00 00 ff d6 50 ff 15 f0 11 00 01 e9 cc 03 00 00 e8 7c 1c 00 " +
				"00 33 f6 56 e8 b1 fc ff ff 85 c0 0f 84 b7 03 00 00 56 6a 02 ff 35 6c 80 00 01 ff " +
				"35 d0 87 00 01 ff 15 cc 11 00 01 85 c0 75 1d 68 10 10 00 00 ff 35 50 80 00 01 ff " +
				"35 44 80 00 01 ff 35 d0 87 00 01 ff 15 04 12 00 01 ff 35 d0 87 00 01 ff 15 2c 12 " +
				"00 01 ff 35 d4 8b 00 01 ff 15 58 10 00 01 e9 64 03 00 00 83 fe 1a 77 47 0f 84 59 " +
				"03 00 00 83 fe 11 0f 85 16 01 00 00 33 f6 39 35 e8 87 00 01 74 22 8b 3d 28 12 00 " +
				"01 56 ff d7 56 ff d7 68 00 10 00 00 ff 35 50 80 00 01 ff 35 88 80 00 01 e9 7d 02 " +
				"00 00 6a 01 e8 0f fc ff ff e9 1a 03 00 00 8b 7d 14 b8 11 01 00 00 3b f0 0f 87 8b " +
				"00 00 00 3b f0 0f 84 16 02 00 00 83 fe 1c 0f 85 bd 00 00 00 33 f6 39 75 10 74 2f " +
				"a1 ec 87 00 01 8b 0d f0 87 00 01 3b c6 75 08 3b ce 0f 84 d9 02 00 00 8b 3d 14 12 " +
				"00 01 51 50 68 b1 00 00 00 ff 35 d4 87 00 01 e9 56 01 00 00 8b 3d 14 12 00 01 68 " +
				"f0 87 00 01 68 ec 87 00 01 68 b0 00 00 00 ff 35 d4 87 00 01 ff d7 a1 ec 87 00 01 " +
				"8b 0d f0 87 00 01 3b c1 75 11 89 35 ec 87 00 01 89 35 f0 87 00 01 e9 84 02 00 00 " +
				"51 50 e9 07 01 00 00 8b ce b8 12 01 00 00 2b c8 0f 84 3c 02 00 00 83 e9 04 0f 84 " +
				"29 02 00 00 49 0f 84 f9 01 00 00 81 e9 1c 01 00 00 0f 84 e0 01 00 00 81 e9 e6 00 " +
				"00 00 0f 84 3d 01 00 00 81 e9 e8 7c 00 00 0f 84 02 01 00 00 3b 35 5c 88 00 01 0f " +
				"85 ee 00 00 00 8b 45 14 8b 48 0c 8b c1 8b d1 f7 d0 c1 ea 02 83 e0 01 83 e2 01 f6 " +
				"c1 08 a3 2c 88 00 01 89 15 28 88 00 01 74 10 ff 35 54 88 00 01 8b 35 e4 11 00 01 " +
				"ff d6 eb 1a f6 c1 10 74 2c ff 35 54 88 00 01 8b 35 e4 11 00 01 ff d6 6a 01 e8 79 " +
				"06 00 00 68 40 8d 00 01 e8 e7 2c 00 00 ff 35 40 8f 00 01 ff d6 e9 c8 01 00 00 f6 " +
				"c1 20 74 6e 33 f6 3b c6 74 06 89 35 2c 88 00 01 ff 35 54 88 00 01 8b 1d e4 11 00 " +
				"01 ff d3 8b 3d 14 12 00 01 56 56 68 b1 00 00 00 ff 35 d4 87 00 01 ff d7 56 e8 28 " +
				"06 00 00 68 40 8d 00 01 e8 96 2c 00 00 3b c6 75 ec ff 35 40 8f 00 01 ff d3 56 56 " +
				"68 b1 00 00 00 ff 35 d4 87 00 01 ff d7 56 56 68 b7 00 00 00 ff 35 d4 87 00 01 ff " +
				"d7 e9 55 01 00 00 f6 c1 40 0f 84 4c 01 00 00 83 25 d8 87 00 01 00 e9 40 01 00 00 " +
				"ff 75 14 e9 b7 00 00 00 33 f6 56 ff 15 24 12 00 01 66 25 ff 03 66 3d 11 00 75 03 " +
				"6a 01 5e 56 6a 01 68 d8 00 00 00 ff 35 d4 87 00 01 ff 15 14 12 00 01 e9 09 01 00 " +
				"00 8b c7 c1 e8 10 66 25 ff 0f 66 3b c2 75 11 6a 00 6a 03 ff 75 08 e8 8b f2 ff ff " +
				"e9 ea 00 00 00 3b 3d d4 87 00 01 75 4c 8b 45 10 c1 e8 10 66 3d 00 05 74 06 66 3d " +
				"01 05 75 3a 83 3d dc 87 00 01 01 75 0f c7 05 dc 87 00 01 02 00 00 00 e9 b8 00 00 " +
				"00 68 10 10 00 00 ff 35 50 80 00 01 ff 35 44 80 00 01 ff 35 d0 87 00 01 ff 15 04 " +
				"12 00 01 e9 96 00 00 00 57 ff 75 10 ff 75 08 e8 26 f2 ff ff 85 c0 0f 85 82 00 00 " +
				"00 57 ff 75 10 56 ff 75 08 ff 15 20 12 00 01 eb 74 ff 75 08 ff 75 10 e8 13 f9 ff " +
				"ff eb 65 83 3d e0 87 00 01 00 74 5c 8b 45 14 c1 e8 10 66 85 c0 74 51 6a 03 68 20 " +
				"f0 00 00 ff 35 58 88 00 01 ff 15 0c 12 00 01 eb 3c ff 75 08 e8 6a 02 00 00 eb 32 " +
				"83 3d e0 87 00 01 00 8b 4d 10 74 18 81 f9 20 f0 00 00 74 1e 81 f9 40 f0 00 00 74 " +
				"16 81 f9 50 f0 00 00 74 0e ff 75 14 51 50 ff 75 08 ff 15 20 12 00 01 33 c0 5f 5e " +
				"5b 5d c2 10 00");

		Function function = createFunction("0x100248f");

		startTransaction();
		function.setBody(new AddressSet(getProgram(), addr("0x100248f"), addr("0x0100294d")));
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x100248f"), addr("0x0100294d")));
	}

	private void createFunction_2cf5() throws Exception, OverlappingFunctionException {
		Function function;
		setBytes("0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 " +
				"8b f8 eb 02 33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 " +
				"85 f6 74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 " +
				"04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 08 ff " +
				"15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14 00");

		Function ghidra = createFunction("0x01002cf5");

		startTransaction();
		ghidra.setBody(new AddressSet(getProgram(), addr("0x01002cf5"), addr("0x01002d6e")));
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x01002cf5"), addr("0x01002d6b")));

		FunctionManager functionManager = getProgram().getFunctionManager();
		startTransaction();
		function = functionManager.getFunctionAt(addr("0x01002cf5"));
		function.setStackPurgeSize(-20);
		endTransaction();

		createLabel("0x01002cf5", "ghidra");
	}

	private void createFunction_48a3() throws Exception, OverlappingFunctionException {
		Function function;
		setBytes("0x010048a3",
			"8b 44 24 04 66 8b 08 66 83 f9 20 74 06 66 83 f9 09 75 04 40 40 eb ed c2 04 00");
		function = createFunction("0x010048a3");
		createLabel("0x010048a3", "doStuff");

		startTransaction();
		function.setBody(new AddressSet(getProgram(), addr("0x010048a3"), addr("0x10048bd")));
		endTransaction();
	}

	private void createFunction_sscanf()
			throws Exception, InvalidInputException, OverlappingFunctionException {

		setBytes("0x0100415a",
			"55 8b ec 83 ec 0c 33 c0 c7 45 f8 01 00 00 00 21 45 fc 39 45 08 c7 45 f4 04 00 00 00 " +
				"74 1a 8d 45 f4 50 8d 45 f8 50 8d 45 fc 50 6a 00 ff 75 0c ff 75 08 ff 15 " +
				"08 10 00 01 85 c0 75 06 83 7d fc 04 74 05 8b 45 10 eb 03 8b 45 f8 c9 c2 0c 00");
		createLabel("0x0100415a", "sscanf");

		startTransaction();
		StringDataType string = new StringDataType();
		DataType pointer = new Pointer32DataType(string);
		Parameter p0 = new ParameterImpl("destStr", pointer, getProgram());
		Parameter p3 = new ParameterImpl("parm_3", DataType.DEFAULT, getProgram());
		Parameter p4 = new ParameterImpl("parm_4", DataType.DEFAULT, getProgram());
		createEmptyFunction("sscanf", "0x0100415a", 78, new Undefined1DataType(), p0, p3, p4);

		ReferenceManager referenceManager = getProgram().getReferenceManager();
		referenceManager.addStackReference(addr("0x0100416c"), 0, 0x4, RefType.READ,
			SourceType.USER_DEFINED);
		endTransaction();

		disassemble(new AddressSet(getProgram(), addr("0x0100415a"), addr("0x010041a7")), false);
	}
}
