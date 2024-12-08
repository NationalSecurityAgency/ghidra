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
package sarif;

import java.util.Date;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramDiff;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;

public class MergeNotepadSarifTest extends AbstractSarifTest {

	private UniversalID lastGeneratedUniversalID;
	private Object consumer;


	public MergeNotepadSarifTest() {
		super();
	}

	@Test
	public void testNotepad() throws Exception {
		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

	protected Program getProgram(String progName) throws Exception {
		return buildNotepadMergeListingTest_X86Program();
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
	
}
