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
/*
 * ProgramDiffTest.java
 *
 * Created on January 3, 2002, 9:55 AM
 */

package ghidra.program.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.*;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ClassicSampleX86ProgramBuilder;

/**
 * <CODE>ProgramDiffTest</CODE> tests the <CODE>ProgramDiff</CODE> class
 * to verify it correctly determines various types of program differences.
 * The setup for this test class loads two programs that were saved to the 
 * testdata directory as XML. The tests will determine the differences between
 * these two programs.
 */
public class ProgramDiff3Test extends AbstractProgramDiffTest {

	/** Creates new ProgramDiffTest */
	public ProgramDiff3Test() {
		super();
	}

	/**
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		programBuilder1 = new ClassicSampleX86ProgramBuilder(false);
		programBuilder2 = new ClassicSampleX86ProgramBuilder(false);
		p1 = programBuilder1.getProgram();
		p2 = programBuilder2.getProgram();
	}

	/**
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		programDiff = null;
		p1 = null;
		p2 = null;
		programBuilder1.dispose();
		programBuilder2.dispose();
		programBuilder1 = null;
		programBuilder2 = null;
	}

	@Test
	public void testExtRefDiff3() throws Exception {
		// 0x1001034: p2 set ExternalName to myGDI32.dll.
	
		programBuilder1.applyDataType("0x01001034", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x01001034", "GDI32.dll", "SomePlace", 0);
	
		programBuilder2.applyDataType("0x01001034", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x01001034", "myGDI32.dll", "SomePlace", 0);
	
		programDiff =
			new ProgramDiff(p1, p2, new AddressSet(addr(p1, 0x01001000), addr(p1, 0x010017ff)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01001034), addr(p1, 0x01001037));
	
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testExtRefDiff4() throws Exception {
		// 0x1001038: p2 set ToLabel to ABC12345.
	
		programBuilder1.applyDataType("0x01001038", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x01001038", "GDI32.dll", "ABC", 0);
	
		programBuilder2.applyDataType("0x01001038", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x01001038", "GDI32.dll", "ABC12345", 0);
	
		programDiff =
			new ProgramDiff(p1, p2, new AddressSet(addr(p1, 0x01001000), addr(p1, 0x010017ff)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01001038), addr(p1, 0x0100103b));
	
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testExtRefDiff5() throws Exception {
		// 0x100103c: p2 set ToAddress to 0x77f4abcd.
	
		programBuilder1.applyDataType("0x0100103c", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x0100103c", "GDI32.dll", "XYZ", "0x77f4cdef", 0);
	
		programBuilder2.applyDataType("0x0100103c", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x0100103c", "GDI32.dll", "XYZ", "0x77f4abcd", 0);
	
		programDiff =
			new ProgramDiff(p1, p2, new AddressSet(addr(p1, 0x01001000), addr(p1, 0x010017ff)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x0100103c), addr(p1, 0x0100103f));
	
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testExtRefDiff6() throws Exception {
		// 0x1001044: p2 added external ref.
	
		programBuilder1.applyDataType("0x01001044", new Pointer32DataType(), 1);
	
		programBuilder2.applyDataType("0x01001044", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x01001044", "GDI32.dll", "MNM", 0);
	
		programDiff =
			new ProgramDiff(p1, p2, new AddressSet(addr(p1, 0x01001000), addr(p1, 0x010017ff)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01001044), addr(p1, 0x01001047));
	
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiffFilter works as expected.
	 */
	@Test
	public void testFilter() throws Exception {
	
		programDiff = new ProgramDiff(p1, p2);
		// Check that default filter has all difference types set.
		assertEquals(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS), programDiff.getFilter());
	
		// See if we set it to no differences, that is what we get.
		programDiff.setFilter(new ProgramDiffFilter());
		assertEquals(new ProgramDiffFilter(), programDiff.getFilter());
	
		// See if we set it to specific differences, that is what we get.
		programDiff.setFilter(new ProgramDiffFilter(
			ProgramDiffFilter.CODE_UNIT_DIFFS | ProgramDiffFilter.COMMENT_DIFFS));
		assertEquals(
			new ProgramDiffFilter(
				ProgramDiffFilter.CODE_UNIT_DIFFS | ProgramDiffFilter.COMMENT_DIFFS),
			programDiff.getFilter());
	}

	/**
	 * Test that ProgramDiff can determine the function bodies are different.
	 */
	@Test
	public void testFunctionBodyDiff() throws Exception {
		int transactionID = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(0x100299e));
		function2.setBody(new AddressSet(addr(0x100299e), addr(0x1002a89)));
		p2.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100299e), addr(0x0100299e));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testFunctionDefaultStackLocalDiff() throws Exception {
	
		// 0x010048a3: created default stack local_1 in p2.
	
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x010048a3));
		programBuilder2.createLocalVariable(function2, null, DataType.DEFAULT, 0x1);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x010048a3), addr(0x010048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	/**
	 * Test that ProgramDiff can determine that function default stack params are
	 * different.
	 */
	@Test
	public void testFunctionDefaultStackParamDiff() throws Exception {
	
		// 0x1002cf5: created default stack param in p2.
		int transactionID = p2.startTransaction("Test Transaction");
		Function function = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		Variable var = new ParameterImpl("variable", DataType.DEFAULT, 0x1c, p2);
		function.addParameter(var, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x1002cf5), addr(0x1002cf5));
		assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine that function local names are
	 * different.
	 */
	@Test
	public void testFunctionLocalNameDiff() throws Exception {
	
		// 0x10059a3: renamed local_18 to numAvailable in p1.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10059a3));
		Variable[] localVariables = function1.getLocalVariables();
		assertEquals(5, localVariables.length);
		assertEquals(-0x18, localVariables[4].getStackOffset());
		localVariables[4].setName("numAvailable", SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10059a3), addr(0x10059a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	/**
	 * Test that ProgramDiff can determine that function parameter names are
	 * different.
	 */
	@Test
	public void testFunctionLocalsDiff() throws Exception {
	
		// 0x10059a3: removed local_18 in p1.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10059a3));
		Variable[] localVariables = function1.getLocalVariables();
		assertEquals(5, localVariables.length);
		assertEquals(-0x18, localVariables[4].getStackOffset());
		function1.removeVariable(localVariables[4]);
		p1.endTransaction(transactionID1, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10059a3), addr(0x10059a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	/**
	 * Test that ProgramDiff can determine that function local types are
	 * different.
	 */
	@Test
	public void testFunctionLocalTypeDiff() throws Exception {
	
		// 0x10059a3: in p1 local_8 is a Undefined, in p2 it's Pointer.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10059a3));
		Variable[] localVariables = function1.getLocalVariables();
		assertEquals(5, localVariables.length);
		assertEquals(-0x8, localVariables[0].getStackOffset());
		localVariables[0].setDataType(DataType.DEFAULT, SourceType.DEFAULT);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10059a3));
		Variable[] localVariables2 = function2.getLocalVariables();
		assertEquals(5, localVariables2.length);
		assertEquals(-0x8, localVariables2[0].getStackOffset());
		localVariables2[0].setDataType(new PointerDataType(), SourceType.DEFAULT);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10059a3), addr(0x10059a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	/**
	 * Test that ProgramDiff can determine the function names are different.
	 */
	@Test
	public void testFunctionNameDiff() throws Exception {
	
		// 0x010048a3: function names differ.
		// 0x01002239: function names same.
		int transactionID = p1.startTransaction("Test Transaction");
		FunctionManager functionManager1 = p1.getFunctionManager();
		Function function1 = functionManager1.getFunctionAt(addr(0x010048a3));
		assertNotNull(function1);
		function1.setName("MyFunction48a3", SourceType.USER_DEFINED);
		function1 = functionManager1.getFunctionAt(addr(0x01002239));
		assertNotNull(function1);
		function1.setName("Function2239", SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		FunctionManager functionManager2 = p2.getFunctionManager();
		Function function2 = functionManager2.getFunctionAt(addr(0x010048a3));
		assertNotNull(function2);
		function2.setName("Other48a3", SourceType.USER_DEFINED);
		function2 = functionManager2.getFunctionAt(addr(0x01002239));
		assertNotNull(function2);
		function2.setName("Function2239", SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x010048a3), addr(0x010048a3));
		assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine there is a function difference when
	 * the function is only in Program1.
	 */
	@Test
	public void testFunctionOnlyInP1() throws Exception {
		// In p1 not in p2.
		int transactionID = p2.startTransaction("Test Transaction");
		p2.getFunctionManager().removeFunction(addr(0x10030d2));
		p2.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(new AddressSet(addr(0x10030d2), addr(0x10030d2)),
			programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine there is a function difference when
	 * the function is only in Program2.
	 */
	@Test
	public void testFunctionOnlyInP2() throws Exception {
		// In p2 and not in p1.
		int transactionID = p1.startTransaction("Test Transaction");
		p1.getFunctionManager().removeFunction(addr(0x10030d2));
		p1.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(new AddressSet(addr(0x10030d2), addr(0x10030d2)),
			programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine that function parameter names are
	 * different.
	 */
	@Test
	public void testFunctionParamNameDiff() throws Exception {
	
		// 0x01002cf5: renamed parm_2 to value in p1.
		int transactionID = p1.startTransaction("Test Transaction");
		Function function = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function.getParameter(0).setName("value", SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x01002cf5), addr(0x01002cf5));
		assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
		 * Test that ProgramDiff can determine that function param offsets are
		 * different.
		 */
		@Test
	    public void testFunctionParamOffsetDiff() throws Exception {
	
			// 0x010032d5: changed param offset from 0x8 to 0x4 in p2.
	
			AddressSet as = new AddressSet();
			as.addRange(addr(0x010032d5), addr(0x010033f5));
			programDiff = new ProgramDiff(p1, p2, as);
			programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			AddressSet diffAs = new AddressSet();
	// For now, we are not allowing you to set the parameter offset or local size outright.
	//        diffAs.addRange(addr(0x010032d5), addr(0x010032d5));
			assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
		}

	/**
	 * Test that ProgramDiff can determine that function parameters are
	 * different.
	 */
	@Test
	public void testFunctionParamsDiff() throws Exception {
	
		// 0x01002cf5: removed parm_2 from p1.
		int transactionID = p1.startTransaction("Test Transaction");
		Function function = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function.removeParameter(0);
		p1.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x01002cf5), addr(0x01002cf5));
		assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine that function parameter types are
	 * different.
	 */
	@Test
	public void testFunctionParamTypeDiff() throws Exception {
	
		// 0x010059a3: in p1 parm_2 is a Word, in p2 it's Undefined.
		int transactionID = p1.startTransaction("Test Transaction");
		FunctionManager functionManager1 = p1.getFunctionManager();
		Function function1 = functionManager1.getFunctionAt(addr(0x010059a3));
		assertEquals(3, function1.getParameterCount());
		Parameter f1p0 = function1.getParameter(0);
		f1p0.setDataType(new WordDataType(), SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		FunctionManager functionManager2 = p2.getFunctionManager();
		Function function2 = functionManager2.getFunctionAt(addr(0x010059a3));
		assertEquals(3, function2.getParameterCount());
		Parameter f2p0 = function2.getParameter(0);
		f2p0.setDataType(DataType.DEFAULT, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x010059a3), addr(0x010059a3));
		assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testFunctionRegParamDiff1() throws Exception {
	
		// program1 has reg param and program2 doesn't.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff10() throws Exception {
	
		// same reg param in program 1 and 2
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function1.removeParameter(0);
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.removeParameter(0);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		function2.removeParameter(0);
		dr0Reg = p2.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.removeParameter(0);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet();
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff11() throws Exception {
	
		// no params in program 1 or 2
	
		AddressSet expectedDiffs = new AddressSet();
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff12() throws Exception {
	
		// changed param from stack to register in program2
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		Register dr0Reg = p2.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.removeParameter(0);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x1002cf5), addr(0x1002cf5));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff13() throws Exception {
	
		// changed param from stack to register in program1
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.removeParameter(0);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x1002cf5), addr(0x1002cf5));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff2() throws Exception {
	
		// different named registers as param_1
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function1.removeParameter(0);
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("example", new DWordDataType(), dr0Reg, p1);
		function1.removeParameter(0);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		function2.removeParameter(0);
		dr0Reg = p2.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.removeParameter(0);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x1002cf5), addr(0x1002cf5));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff3() throws Exception {
	
		// program2 has reg param and program1 doesn't.
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		Register eaxReg = p2.getRegister("EAX");
		Variable var2 = new ParameterImpl("count", new DWordDataType(), eaxReg, p2);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff4() throws Exception {
	
		// same named registers for params 0,1,2 but different name for 0.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register eaxReg = p1.getRegister("EAX");
		Register ecxReg = p1.getRegister("ECX");
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1A = new ParameterImpl("Units", new DWordDataType(), eaxReg, p1);
		function1.addParameter(var1A, SourceType.USER_DEFINED);
		Variable var1B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p1);
		function1.addParameter(var1B, SourceType.USER_DEFINED);
		Variable var1C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p1);
		function1.addParameter(var1C, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		eaxReg = p2.getRegister("EAX");
		ecxReg = p2.getRegister("ECX");
		dr0Reg = p2.getRegister("DR0");
		Variable var2A = new ParameterImpl("One", new DWordDataType(), eaxReg, p2);
		function2.addParameter(var2A, SourceType.USER_DEFINED);
		Variable var2B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p2);
		function2.addParameter(var2B, SourceType.USER_DEFINED);
		Variable var2C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p2);
		function2.addParameter(var2C, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff5() throws Exception {
	
		// same named registers for params 0,1,2 but different dt for 1.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register eaxReg = p1.getRegister("EAX");
		Register ecxReg = p1.getRegister("ECX");
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1A = new ParameterImpl("One", new DWordDataType(), eaxReg, p1);
		function1.addParameter(var1A, SourceType.USER_DEFINED);
		Variable var1B =
			new ParameterImpl("Two", new PointerDataType(new WordDataType()), ecxReg, p1);
		function1.addParameter(var1B, SourceType.USER_DEFINED);
		Variable var1C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p1);
		function1.addParameter(var1C, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		eaxReg = p2.getRegister("EAX");
		ecxReg = p2.getRegister("ECX");
		dr0Reg = p2.getRegister("DR0");
		Variable var2A = new ParameterImpl("One", new DWordDataType(), eaxReg, p2);
		function2.addParameter(var2A, SourceType.USER_DEFINED);
		Variable var2B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p2);
		function2.addParameter(var2B, SourceType.USER_DEFINED);
		Variable var2C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p2);
		function2.addParameter(var2C, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff6() throws Exception {
	
		// same named registers for params 0,1,2 but different comment for 2.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register eaxReg = p1.getRegister("EAX");
		Register ecxReg = p1.getRegister("ECX");
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1A = new ParameterImpl("One", new DWordDataType(), eaxReg, p1);
		function1.addParameter(var1A, SourceType.USER_DEFINED);
		Variable var1B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p1);
		function1.addParameter(var1B, SourceType.USER_DEFINED);
		Variable var1C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p1);
		var1C.setComment("Third Param");
		function1.addParameter(var1C, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		eaxReg = p2.getRegister("EAX");
		ecxReg = p2.getRegister("ECX");
		dr0Reg = p2.getRegister("DR0");
		Variable var2A = new ParameterImpl("One", new DWordDataType(), eaxReg, p2);
		function2.addParameter(var2A, SourceType.USER_DEFINED);
		Variable var2B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p2);
		function2.addParameter(var2B, SourceType.USER_DEFINED);
		Variable var2C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p2);
		function2.addParameter(var2C, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff7() throws Exception {
	
		// different named registers as different params.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Register clReg = p1.getRegister("CL");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		function1.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true,
			SourceType.USER_DEFINED, new ParameterImpl(null, DataType.DEFAULT, clReg, p1),
			new ParameterImpl(null, DataType.DEFAULT, 0x8, p1),
			new ParameterImpl(null, DataType.DEFAULT, 0xc, p1));
		assertEquals(3, function1.getParameterCount());
		p1.endTransaction(transactionID1, true);
	
		int transactionID = p2.startTransaction("Test Transaction");
		Register dlReg = p2.getRegister("DL");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		function2.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true,
			SourceType.USER_DEFINED, new ParameterImpl(null, DataType.DEFAULT, 0x4, p2),
			new ParameterImpl(null, DataType.DEFAULT, 0x8, p2),
			new ParameterImpl(null, DataType.DEFAULT, dlReg, p2));
		assertEquals(3, function2.getParameterCount());
		p2.endTransaction(transactionID, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	@Test
	public void testFunctionRegParamDiff8() throws Exception {
	
		// added register param in program1
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.addParameter(var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

}
