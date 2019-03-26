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
package ghidra.app.merge.listing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.*;

import generic.stl.Pair;
import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitorAdapter;

public class VariableStorageConflictsTest extends AbstractGenericTest {

	private Program program;

//	private TestEnv testEnv;

	public VariableStorageConflictsTest() {
		super();
		// TODO Auto-generated constructor stub
	}

	@Before
	public void setUp() throws Exception {
//		testEnv = new TestEnv();
		program = buildProgram();
		program.startTransaction("Testing");
	}

	@After
	public void tearDown() throws Exception {
//		testEnv.release(program);
//		testEnv.dispose();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DiffTestPgm1", ProgramBuilder._X86, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);

		// for FunctionMergeManager2Test
		//
		DataType stringPtr = new PointerDataType(new StringDataType());
		DataType byteArray = new ArrayDataType(new ByteDataType(), 1, 1);
		DataType byteArray2 = new ArrayDataType(byteArray, 1, 2);
		DataType byteArray3 = new ArrayDataType(byteArray2, 2, 2);
		program = builder.getProgram();
		Parameter p1 = new ParameterImpl("destStr", stringPtr, 0x8, program);
		Parameter p2 = new ParameterImpl("param_3", DataType.DEFAULT, 0xc, program);
		Parameter p3 = new ParameterImpl("param_4", DataType.DEFAULT, 0x10, program);

		builder.createEmptyFunction(null, null, null, true, "100415a", 10, null, p1, p2, p3);

		p1 = new ParameterImpl("param_1", stringPtr, 0x8, program);
		p2 = new ParameterImpl("param_2", byteArray3, 0xc, program);
		p3 = new ParameterImpl("param_3", new PointerDataType(), 0x10, program);
		Parameter p4 = new ParameterImpl("param_4", new PointerDataType(), 0x14, program);
		Parameter p5 = new ParameterImpl("param_5", byteArray3, 0x18, program);
		builder.createEmptyFunction(null, null, null, true, "1002cf5", 10, null, p1, p2, p3, p4,
			p5);
		builder.createStackReference("1002cf5", RefType.READ, -0x8, SourceType.USER_DEFINED, 0);
		builder.createStackReference("1002cf5", RefType.READ, -0xc, SourceType.USER_DEFINED, 0);

		builder.setProperty(Program.DATE_CREATED, new Date(100000000));// arbitrary, but consistent

		builder.setRegisterValue("DR0", "10022d4", "10022e5", 0x1010101);
		builder.setRegisterValue("DR0", "100230b", "100231c", 0xa4561427);
		builder.setRegisterValue("DR0", "1002329", "100233b", 0x40e20100);
		builder.setRegisterValue("DR0", "1003bfc", "1003c10", 0x91ef0600);
		builder.setRegisterValue("DR0", "1003c1c", "1003c36", 0x71f25b2e);

		return builder.getProgram();
	}

	@Test
    public void testVariableOverlapNoDifference() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));

		Register axReg = program.getRegister("AX");

		func1.insertParameter(0, new ParameterImpl(null, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func1,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("No conflict expected", !vsc.hasOverlapConflict());

	}

	/**
	
	    
	
	Function@0x100415a
	
	             string *        Stack[0x8]:4        destStr                 XREF[2,0]:   0100416c(R),       
	                                                                                      01004189(R)  
	             undefined       Stack[0xc]:1        parm_3                  XREF[1,0]:   01004186(R)        
	             undefined       Stack[0x10]:1       parm_4                  XREF[1,0]:   0100419c(R)        
	             dword           Stack[-0x4]:4       i                       XREF[3,0]:   01004169(R),       
	                                                                                      01004180(R), 
	                                                                                      01004196(R)  
	             float           Stack[-0x8]:4       count                   XREF[3,0]:   01004162(R),       
	                                                                                      0100417c(R), 
	                                                                                      010041a1(R)  
	             byte            Stack[-0xc]:1       formatCount           
	             
	Function@0x1002cf5L
	
	             IntStruct * *   Stack[0x8]:4        param_1                 XREF[2,0]:   01002d3e(R),       
	                                                                                      01002d5b(R)  
	             byte[2][1][2]   Stack[0xc]:4        param_2                 XREF[2,0]:   01002d3a(R),       
	                                                                                      01002d55(R)  
	             undefined * *   Stack[0x10]:4       param_3                 XREF[3,0]:   01002d11(R),       
	                                                                                      01002d2f(R), 
	                                                                                      01002d58(R)  
	             undefined * *   Stack[0x14]:4       param_4                 XREF[3,0]:   01002cf8(R),       
	                                                                                      01002d06(R), 
	                                                                                      01002d2c(R)  
	             CoolUnion[3][2  Stack[0x18]:2880    param_5                 XREF[2,0]:   01002d37(R),   
	
	**/

	@Test
    public void testVariableStackParameterConflict() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		// Stack[0xc]:1 conflicts with Stack[0xc]:4
		// Stack[0x10]:1 conflicts with Stack[0x10]:4
		// Since these are params all params should be lumped together

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Parameter conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());
		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);
		assertListEqualUnordered("Expected all/only parameters to overlap",
			Arrays.asList(func1.getParameters()), pair.first);
		assertListEqualUnordered("Expected all/only parameters to overlap",
			Arrays.asList(func2.getParameters()), pair.second);

	}

	private void removeAllVariables(Function func) {
		for (Variable var : func.getAllVariables()) {
			func.removeVariable(var);
		}
	}

	@Test
    public void testVariableMixedParameterLocalConflict() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		Register axReg = program.getRegister("AX");

		func1.insertParameter(0, new ParameterImpl(null, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);

		removeAllVariables(func2);
		func2.addLocalVariable(
			new LocalVariableImpl(null, 0, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Parameter conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());
		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);
		assertListEqualUnordered("Expected all/only parameters to overlap",
			Arrays.asList(func1.getParameters()), pair.first);
		assertListEqualUnordered("Expected locals to overlap",
			Arrays.asList(func2.getLocalVariables()), pair.second);

	}

	@Test
    public void testVariableLocalConflict() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		Register axReg = program.getRegister("AX");
		Register bxReg = program.getRegister("BX");

		func1.addLocalVariable(
			new LocalVariableImpl(null, 0, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);
		func1.addLocalVariable(
			new LocalVariableImpl(null, 0, WordDataType.dataType, bxReg, program),
			SourceType.DEFAULT);

		func2.replaceParameters(Arrays.asList(func1.getParameters()),
			FunctionUpdateType.CUSTOM_STORAGE, false, func1.getSignatureSource());
		func2.addLocalVariable(new LocalVariableImpl(null, 0, DWordDataType.dataType,
			axReg.getParentRegister(), program), SourceType.DEFAULT);
		func2.addLocalVariable(new LocalVariableImpl(null, 0x10, DWordDataType.dataType,
			bxReg.getParentRegister(), program), SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Local conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());
		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);
		assertEquals("Expected single local to overlap", 1, pair.first.size());
		Variable var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(axReg, var1.getVariableStorage().getRegister());

		assertEquals("Expected single local overlap", 1, pair.second.size());
		Variable var2 = pair.second.get(0);
		assertTrue("Expected single local to overlap", !(var2 instanceof Parameter));
		assertEquals(axReg.getParentRegister(), var2.getVariableStorage().getRegister());
	}

	@Test
    public void testVariableLocalConflict2() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		Register axReg = program.getRegister("AX");
		Register bxReg = program.getRegister("BX");

		func1.addLocalVariable(
			new LocalVariableImpl(null, 0, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);
		func1.addLocalVariable(
			new LocalVariableImpl(null, 0x10, WordDataType.dataType, bxReg, program),
			SourceType.DEFAULT);

		func2.replaceParameters(Arrays.asList(func1.getParameters()),
			FunctionUpdateType.CUSTOM_STORAGE, false, func1.getSignatureSource());
		func2.addLocalVariable(new LocalVariableImpl(null, 0, DWordDataType.dataType,
			axReg.getParentRegister(), program), SourceType.DEFAULT);
		func2.addLocalVariable(new LocalVariableImpl(null, 0x10, DWordDataType.dataType,
			bxReg.getParentRegister(), program), SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Local conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(2, overlappingVariables.size());

		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);
		assertEquals("Expected single local to overlap", 1, pair.first.size());
		Variable var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(axReg, var1.getVariableStorage().getRegister());

		assertEquals("Expected single local overlap", 1, pair.second.size());
		Variable var2 = pair.second.get(0);
		assertTrue("Expected single local to overlap", !(var2 instanceof Parameter));
		assertEquals(axReg.getParentRegister(), var2.getVariableStorage().getRegister());

		pair = overlappingVariables.get(1);
		assertEquals("Expected single local to overlap", 1, pair.first.size());
		var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(bxReg, var1.getVariableStorage().getRegister());

		assertEquals("Expected single local overlap", 1, pair.second.size());
		var2 = pair.second.get(0);
		assertTrue("Expected single local to overlap", !(var2 instanceof Parameter));
		assertEquals(bxReg.getParentRegister(), var2.getVariableStorage().getRegister());
	}

	@Test
    public void testVariableLocalConflict3() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		func1.addLocalVariable(new LocalVariableImpl(null, DWordDataType.dataType, -0x20, program),
			SourceType.DEFAULT);
		func1.addLocalVariable(new LocalVariableImpl(null, DWordDataType.dataType, -0x1c, program),
			SourceType.DEFAULT);

		func2.replaceParameters(Arrays.asList(func1.getParameters()),
			FunctionUpdateType.CUSTOM_STORAGE, false, func1.getSignatureSource());
		func2.addLocalVariable(new LocalVariableImpl(null, DWordDataType.dataType, -0x1e, program),
			SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Local conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());
		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);

		assertEquals("Expected two locals to overlap", 2, pair.first.size());
		Variable var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(-0x20, var1.getVariableStorage().getStackOffset());
		var1 = pair.first.get(1);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(-0x1c, var1.getVariableStorage().getStackOffset());

		assertEquals("Expected single local overlap", 1, pair.second.size());
		Variable var2 = pair.second.get(0);
		assertTrue("Expected single local to overlap", !(var2 instanceof Parameter));
		assertEquals(-0x1e, var2.getVariableStorage().getStackOffset());
	}

	@Test
    public void testVariableLocalConflict4() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		func1.addLocalVariable(new LocalVariableImpl(null, QWordDataType.dataType, -0x20, program),
			SourceType.DEFAULT);

		func2.replaceParameters(Arrays.asList(func1.getParameters()),
			FunctionUpdateType.CUSTOM_STORAGE, false, func1.getSignatureSource());
		func2.addLocalVariable(new LocalVariableImpl(null, DWordDataType.dataType, -0x1e, program),
			SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Local conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());
		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);

		assertEquals("Expected two locals to overlap", 1, pair.first.size());
		Variable var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(-0x20, var1.getVariableStorage().getStackOffset());

		assertEquals("Expected single local overlap", 1, pair.second.size());
		Variable var2 = pair.second.get(0);
		assertTrue("Expected single local to overlap", !(var2 instanceof Parameter));
		assertEquals(-0x1e, var2.getVariableStorage().getStackOffset());
	}

	@Test
    public void testVariableCompoundLocalConflict() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		Register axReg = program.getRegister("AX");
		Register bxReg = program.getRegister("BX");

		VariableStorage axbxStorage = new VariableStorage(program, axReg, bxReg);
		func1.addLocalVariable(
			new LocalVariableImpl(null, 0, DWordDataType.dataType, axbxStorage, program),
			SourceType.DEFAULT);

		func2.replaceParameters(Arrays.asList(func1.getParameters()),
			FunctionUpdateType.CUSTOM_STORAGE, false, func1.getSignatureSource());
		func2.addLocalVariable(
			new LocalVariableImpl(null, 0, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);
		func2.addLocalVariable(
			new LocalVariableImpl(null, 0x10, WordDataType.dataType, bxReg, program),
			SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Local conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());

		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);
		assertEquals("Expected single local to overlap", 1, pair.first.size());
		Variable var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(axbxStorage, var1.getVariableStorage());

		assertEquals("Expected two locals to overlap", 1, pair.second.size());
		Variable var2 = pair.second.get(0);
		assertTrue("Expected single local to overlap", !(var2 instanceof Parameter));
		assertEquals(axReg, var2.getVariableStorage().getRegister());
	}

	@Test
    public void testVariableCompoundLocalConflict2() throws Exception {

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		Function func1 = listing.getFunctionAt(space.getAddress(0x100415aL));
		Function func2 = listing.getFunctionAt(space.getAddress(0x1002cf5L));

		Register axReg = program.getRegister("AX");
		Register bxReg = program.getRegister("BX");

		VariableStorage axbxStorage = new VariableStorage(program, axReg, bxReg);
		func1.addLocalVariable(
			new LocalVariableImpl(null, 0x10, DWordDataType.dataType, axbxStorage, program),
			SourceType.DEFAULT);

		func2.replaceParameters(Arrays.asList(func1.getParameters()),
			FunctionUpdateType.CUSTOM_STORAGE, false, func1.getSignatureSource());
		func2.addLocalVariable(
			new LocalVariableImpl(null, 0x10, WordDataType.dataType, axReg, program),
			SourceType.DEFAULT);
		func2.addLocalVariable(
			new LocalVariableImpl(null, 0x10, WordDataType.dataType, bxReg, program),
			SourceType.DEFAULT);

		FunctionVariableStorageConflicts vsc = new FunctionVariableStorageConflicts(func1, func2,
			false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue("Local conflict expected", vsc.hasOverlapConflict());

		List<Pair<List<Variable>, List<Variable>>> overlappingVariables =
			vsc.getOverlappingVariables();
		assertEquals(1, overlappingVariables.size());

		Pair<List<Variable>, List<Variable>> pair = overlappingVariables.get(0);
		assertEquals("Expected single local to overlap", 1, pair.first.size());
		Variable var1 = pair.first.get(0);
		assertTrue("Expected single local to overlap", !(var1 instanceof Parameter));
		assertEquals(axbxStorage, var1.getVariableStorage());

		assertEquals("Expected two locals to overlap", 2, pair.second.size());
		Variable var2 = pair.second.get(0);
		assertTrue("Expected two locals to overlap", !(var2 instanceof Parameter));
		assertEquals(axReg, var2.getVariableStorage().getRegister());

		var2 = pair.second.get(1);
		assertTrue("Expected two locals to overlap", !(var2 instanceof Parameter));
		assertEquals(bxReg, var2.getVariableStorage().getRegister());
	}
}
