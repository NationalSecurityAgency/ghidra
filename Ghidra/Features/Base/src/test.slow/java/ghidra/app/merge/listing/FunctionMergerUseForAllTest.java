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

import static org.junit.Assert.*;

import java.awt.Window;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramDiff;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.util.task.TaskMonitorAdapter;

public class FunctionMergerUseForAllTest extends AbstractListingMergeManagerTest {

	private final static String THUNK_A_ENTRY = "00401bd0";
	private final static String THUNK_A_END = "00401bd9";
	private final static String THUNK_A_ALT_END = "00401bdc";
	private final static String THUNK_B_ENTRY = "00401bf0";
	private final static String THUNK_B_END = "00401bf9";
	private final static String THUNK_B_ALT_END = "00401bfc";
	private final static String NO_PARAMS_ENTRY = "004011f0";
	private final static String ONE_PARAM_ENTRY_A = "00401000";
	private final static String ONE_PARAM_ENTRY_B = "00401040";
	private final static String TWO_PARAMS_ENTRY = "004011a0";

	private void setupThunkFunctionUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with two params.
					AddressSet bodyA =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmdA = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), bodyA, addr(program, TWO_PARAMS_ENTRY));
					boolean createdA = cmdA.applyTo(program);
					if (!createdA) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}

					// Create a thunk to the function with one param.
					AddressSet bodyB =
						new AddressSet(addr(program, THUNK_B_ENTRY), addr(program, THUNK_B_END));
					CreateThunkFunctionCmd cmdB = new CreateThunkFunctionCmd(
						addr(program, THUNK_B_ENTRY), bodyB, addr(program, ONE_PARAM_ENTRY_A));
					boolean createdB = cmdB.applyTo(program);
					if (!createdB) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with no params.
					AddressSet bodyA =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmdA = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), bodyA, addr(program, NO_PARAMS_ENTRY));
					boolean createdA = cmdA.applyTo(program);
					if (!createdA) {
						Assert.fail("Couldn't create thunk in Private program.");
					}

					// Create a thunk to the function with no params.
					AddressSet bodyB =
						new AddressSet(addr(program, THUNK_B_ENTRY), addr(program, THUNK_B_END));
					CreateThunkFunctionCmd cmdB = new CreateThunkFunctionCmd(
						addr(program, THUNK_B_ENTRY), bodyB, addr(program, ONE_PARAM_ENTRY_B));
					boolean createdB = cmdB.applyTo(program);
					if (!createdB) {
						Assert.fail("Couldn't create thunk in Private program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	@Test
	public void testThunkFunctionDontUseForAll() throws Exception {

		setupThunkFunctionUseForAll();

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		expectedDifferences.add(addr(resultProgram, THUNK_B_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve Thunk Function Conflict", MY_BUTTON, false);
		chooseButtonAndApply("Resolve Thunk Function Conflict", MY_BUTTON, false);

		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();

		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());

		Function functionB = functionManager.getFunctionAt(addr(resultProgram, THUNK_B_ENTRY));
		assertNotNull(functionB);
		Function thunkedFunctionB = functionB.getThunkedFunction(false);
		assertEquals(addr(resultProgram, ONE_PARAM_ENTRY_B), thunkedFunctionB.getEntryPoint());
	}

	@Test
	public void testThunkFunctionUseForAll() throws Exception {

		setupThunkFunctionUseForAll();

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		expectedDifferences.add(addr(resultProgram, THUNK_B_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve Thunk Function Conflict", MY_BUTTON, true);
//		chooseButtonAndApply("Resolve Thunk Function Conflict", MY_BUTTON, false); // Handled by Use For All.

		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();

		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, NO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());

		Function functionB = functionManager.getFunctionAt(addr(resultProgram, THUNK_B_ENTRY));
		assertNotNull(functionB);
		Function thunkedFunctionB = functionB.getThunkedFunction(false);
		assertEquals(addr(resultProgram, ONE_PARAM_ENTRY_B), thunkedFunctionB.getEntryPoint());
	}

	private void setupFunctionBodyUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with two params.
					AddressSet bodyA =
						new AddressSet(addr(program, THUNK_A_ENTRY), addr(program, THUNK_A_END));
					CreateThunkFunctionCmd cmdA = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), bodyA, addr(program, TWO_PARAMS_ENTRY));
					boolean createdA = cmdA.applyTo(program);
					if (!createdA) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}

					// Create a thunk to the function with one param.
					AddressSet bodyB =
						new AddressSet(addr(program, THUNK_B_ENTRY), addr(program, THUNK_B_END));
					CreateThunkFunctionCmd cmdB = new CreateThunkFunctionCmd(
						addr(program, THUNK_B_ENTRY), bodyB, addr(program, ONE_PARAM_ENTRY_A));
					boolean createdB = cmdB.applyTo(program);
					if (!createdB) {
						Assert.fail("Couldn't create thunk in Latest program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// Change My program.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// Create a thunk to the function with two params.
					AddressSet bodyA = new AddressSet(addr(program, THUNK_A_ENTRY),
						addr(program, THUNK_A_ALT_END));
					CreateThunkFunctionCmd cmdA = new CreateThunkFunctionCmd(
						addr(program, THUNK_A_ENTRY), bodyA, addr(program, TWO_PARAMS_ENTRY));
					boolean createdA = cmdA.applyTo(program);
					if (!createdA) {
						Assert.fail("Couldn't create thunk in My program.");
					}

					// Create a thunk to the function with one param.
					AddressSet bodyB = new AddressSet(addr(program, THUNK_B_ENTRY),
						addr(program, THUNK_B_ALT_END));
					CreateThunkFunctionCmd cmdB = new CreateThunkFunctionCmd(
						addr(program, THUNK_B_ENTRY), bodyB, addr(program, ONE_PARAM_ENTRY_A));
					boolean createdB = cmdB.applyTo(program);
					if (!createdB) {
						Assert.fail("Couldn't create thunk in My program.");
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	@Test
	public void testFunctionBodyConflictDontUseForAll() throws Exception {

		setupFunctionBodyUseForAll();

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		expectedDifferences.add(addr(resultProgram, THUNK_B_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve Function Body Conflict", MY_BUTTON, false);
		chooseButtonAndApply("Resolve Function Body Conflict", MY_BUTTON, false);

		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();

		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		AddressSet bodyA = new AddressSet(addr(resultProgram, THUNK_A_ENTRY),
			addr(resultProgram, THUNK_A_ALT_END));
		assertEquals(bodyA, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());

		Function functionB = functionManager.getFunctionAt(addr(resultProgram, THUNK_B_ENTRY));
		assertNotNull(functionB);
		AddressSet bodyB = new AddressSet(addr(resultProgram, THUNK_B_ENTRY),
			addr(resultProgram, THUNK_B_ALT_END));
		assertEquals(bodyB, functionB.getBody());
		Function thunkedFunctionB = functionB.getThunkedFunction(false);
		assertEquals(addr(resultProgram, ONE_PARAM_ENTRY_A), thunkedFunctionB.getEntryPoint());
	}

	@Test
	public void testFunctionBodyConflictUseForAll() throws Exception {

		setupFunctionBodyUseForAll();

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();
		AddressSet expectedDifferences =
			new AddressSet(addr(resultProgram, THUNK_A_ENTRY), addr(resultProgram, THUNK_A_ENTRY));
		expectedDifferences.add(addr(resultProgram, THUNK_B_ENTRY));
		// Perform the Diff and check the differences.
		ProgramDiff programDiff = new ProgramDiff(resultProgram, myProgram);
		AddressSetView differences = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, differences);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDifferences =
			programDiff.getDifferences(filter, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(expectedDifferences, functionDifferences);

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve Function Body Conflict", MY_BUTTON, true);
//		chooseButtonAndApply("Resolve Function Body Conflict", MY_BUTTON, false); // Handled by Use For All

		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();

		Function function = functionManager.getFunctionAt(addr(resultProgram, THUNK_A_ENTRY));
		assertNotNull(function);
		AddressSet bodyA = new AddressSet(addr(resultProgram, THUNK_A_ENTRY),
			addr(resultProgram, THUNK_A_ALT_END));
		assertEquals(bodyA, function.getBody());
		Function thunkedFunction = function.getThunkedFunction(false);
		assertEquals(addr(resultProgram, TWO_PARAMS_ENTRY), thunkedFunction.getEntryPoint());

		Function functionB = functionManager.getFunctionAt(addr(resultProgram, THUNK_B_ENTRY));
		assertNotNull(functionB);
		AddressSet bodyB = new AddressSet(addr(resultProgram, THUNK_B_ENTRY),
			addr(resultProgram, THUNK_B_ALT_END));
		assertEquals(bodyB, functionB.getBody());
		Function thunkedFunctionB = functionB.getThunkedFunction(false);
		assertEquals(addr(resultProgram, ONE_PARAM_ENTRY_A), thunkedFunctionB.getEntryPoint());
	}

	private void setupFunctionReturnUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// Change the Latest program which will also be used for Result program.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, NO_PARAMS_ENTRY);
					assertNotNull(function1);
					Function function2 = getFunction(program, TWO_PARAMS_ENTRY);
					assertNotNull(function2);
					function1.setReturnType(new ByteDataType(), SourceType.USER_DEFINED);
					function2.setReturnType(new FloatDataType(), SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// Change My program.
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, NO_PARAMS_ENTRY);
					assertNotNull(function1);
					Function function2 = getFunction(program, TWO_PARAMS_ENTRY);
					assertNotNull(function2);
					function1.setReturnType(new CharDataType(), SourceType.USER_DEFINED);
					function2.setReturnType(new DWordDataType(), SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	@Test
	public void testFunctionReturnConflictDontUseForAll() throws Exception {

		setupFunctionReturnUseForAll();

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, false);
		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, false);

		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();

		Function function1 = functionManager.getFunctionAt(addr(resultProgram, NO_PARAMS_ENTRY));
		assertNotNull(function1);
		Function function2 = functionManager.getFunctionAt(addr(resultProgram, TWO_PARAMS_ENTRY));
		assertNotNull(function2);

		assertTrue(new CharDataType().isEquivalent(function1.getReturnType()));
		assertTrue(new DWordDataType().isEquivalent(function2.getReturnType()));
	}

	@Test
	public void testFunctionReturnConflictUseForAll() throws Exception {

		setupFunctionReturnUseForAll();

		resultProgram = mtf.getResultProgram();
		myProgram = mtf.getPrivateProgram();

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, true);
//		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, false); // Handled by Use For All

		waitForMergeCompletion();

		FunctionManager functionManager = resultProgram.getFunctionManager();

		Function function1 = functionManager.getFunctionAt(addr(resultProgram, NO_PARAMS_ENTRY));
		assertNotNull(function1);
		Function function2 = functionManager.getFunctionAt(addr(resultProgram, TWO_PARAMS_ENTRY));
		assertNotNull(function2);

		assertTrue(new CharDataType().isEquivalent(function1.getReturnType()));
		assertTrue(new DWordDataType().isEquivalent(function2.getReturnType()));
	}

	@Test
	public void testLocalVarsConflictDontUseForAll() throws Exception {

		final Variable[] latestLocal4 = new Variable[1];
		final Variable[] latestLocal8 = new Variable[1];
		final Variable[] latestLocalC = new Variable[1];
		final Variable[] existingLocal = new Variable[1];
		final Variable[] myLocal4 = new Variable[1];
		final Variable[] myLocala = new Variable[1];
		final Variable[] myLocal30 = new Variable[1];

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");
					Function function2 = getFunction(program, "0x004012c0");
					Variable[] localVariables = function2.getLocalVariables();
					assertEquals(1, localVariables.length);

					latestLocal4[0] =
						new LocalVariableImpl("local_4", new ByteDataType(), -4, program);
					latestLocal8[0] =
						new LocalVariableImpl("local_8", new Undefined4DataType(), -8, program);
					latestLocalC[0] =
						new LocalVariableImpl("local_c", new ByteDataType(), -0xc, program);

					function1.addLocalVariable(latestLocal4[0], SourceType.USER_DEFINED);
					function1.addLocalVariable(latestLocal8[0], SourceType.USER_DEFINED);

					function2.addLocalVariable(latestLocalC[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");
					Function function2 = getFunction(program, "0x004012c0");

					myLocal4[0] = new LocalVariableImpl("local_4", new WordDataType(), -4, program);
					myLocala[0] =
						new LocalVariableImpl("local_a", new Undefined4DataType(), -0xa, program);
					myLocal30[0] =
						new LocalVariableImpl("local_30", new ByteDataType(), -0x30, program);

					function1.addLocalVariable(myLocal4[0], SourceType.USER_DEFINED);
					function1.addLocalVariable(myLocala[0], SourceType.USER_DEFINED);

					function2.addLocalVariable(myLocal30[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		existingLocal[0] =
			new LocalVariableImpl("local_8", new Undefined4DataType(), -8, resultProgram);

		executeMerge(ASK_USER);

		chooseRadioButton(LATEST_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false);// stack overlap: -0x4:1 vs. -0x4:2 @ 00401150 - pick LATEST
		setUseForAll(false, ScrollingListChoicesPanel.class);
		chooseApply();

		chooseRadioButton(CHECKED_OUT_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false);// stack overlap: -0xa:4 vs. -0x8:4 @ 00401150 - pick CHECKED_OUT
		setUseForAll(false, ScrollingListChoicesPanel.class);
		chooseApply();

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		Function function2 = getFunction(resultProgram, "0x004012c0");

		Variable[] vars = function1.getLocalVariables();
		assertEquals(2, vars.length);
		assertEquals(latestLocal4[0], vars[0]);
		assertEquals(myLocala[0], vars[1]);

		vars = function2.getLocalVariables();
		assertEquals(3, vars.length);
		assertEquals(existingLocal[0], vars[0]);
		assertEquals(latestLocalC[0], vars[1]);
		assertEquals(myLocal30[0], vars[2]);
	}

	@Test
	public void testLocalVarsConflictUseForAll() throws Exception {

		final Variable[] latestLocal4 = new Variable[1];
		final Variable[] latestLocal8 = new Variable[1];
		final Variable[] latestLocalC = new Variable[1];
		final Variable[] existingLocal = new Variable[1];
		final Variable[] myLocal4 = new Variable[1];
		final Variable[] myLocala = new Variable[1];
		final Variable[] myLocal30 = new Variable[1];

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");
					Function function2 = getFunction(program, "0x004012c0");
					Variable[] localVariables = function2.getLocalVariables();
					assertEquals(1, localVariables.length);

					latestLocal4[0] =
						new LocalVariableImpl("local_4", new ByteDataType(), -4, program);
					latestLocal8[0] =
						new LocalVariableImpl("local_8", new Undefined4DataType(), -8, program);
					latestLocalC[0] =
						new LocalVariableImpl("local_c", new ByteDataType(), -0xc, program);

					function1.addLocalVariable(latestLocal4[0], SourceType.USER_DEFINED);
					function1.addLocalVariable(latestLocal8[0], SourceType.USER_DEFINED);

					function2.addLocalVariable(latestLocalC[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");
					Function function2 = getFunction(program, "0x004012c0");

					myLocal4[0] = new LocalVariableImpl("local_4", new WordDataType(), -4, program);
					myLocala[0] =
						new LocalVariableImpl("local_a", new Undefined4DataType(), -0xa, program);
					myLocal30[0] =
						new LocalVariableImpl("local_30", new ByteDataType(), -0x30, program);

					function1.addLocalVariable(myLocal4[0], SourceType.USER_DEFINED);
					function1.addLocalVariable(myLocala[0], SourceType.USER_DEFINED);

					function2.addLocalVariable(myLocal30[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		existingLocal[0] =
			new LocalVariableImpl("local_8", new Undefined4DataType(), -8, resultProgram);

		executeMerge(ASK_USER);

		chooseRadioButton(CHECKED_OUT_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false);// stack overlap: -0x4:1 vs. -0x4:2 @ 00401150 - pick LATEST
		setUseForAll(true, ScrollingListChoicesPanel.class);
		chooseApply();

// Handled by Use For All.
//		chooseRadioButton(CHECKED_OUT_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false); // stack overlap: -0xa:4 vs. -0x8:4 @ 00401150 - pick CHECKED_OUT
//		setUseForAll(false, ScrollingListChoicesPanel.class);
//		chooseApply();

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		Function function2 = getFunction(resultProgram, "0x004012c0");

		Variable[] vars = function1.getLocalVariables();
		assertEquals(2, vars.length);
		assertEquals(myLocal4[0], vars[0]);
		assertEquals(myLocala[0], vars[1]);

		vars = function2.getLocalVariables();
		assertEquals(3, vars.length);
		assertEquals(existingLocal[0], vars[0]);
		assertEquals(latestLocalC[0], vars[1]);
		assertEquals(myLocal30[0], vars[2]);
	}

	private void setupParamInfoConflictUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x004019ac");
					func.getParameter(2).setComment("Latest comment 004019ac_2.");

					func = getFunction(program, "0x00401150");
					func.getParameter(0).setComment("Latest comment 00401150_0.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x004019ac");
					func.getParameter(2).setComment("My comment 004019ac_2.");

					func = getFunction(program, "0x00401150");
					func.getParameter(0).setComment("My comment 00401150_0.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	@Test
	public void testParamInfoConflictDontUseForAll() throws Exception {
		setupParamInfoConflictUseForAll();

		executeMerge(ASK_USER);
		chooseVariousOptions("0x00401150", new int[] { INFO_ROW, KEEP_LATEST }, false);
		chooseVariousOptions("0x004019ac", new int[] { INFO_ROW, KEEP_MY }, false);
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x004019ac");
		assertEquals("My comment 004019ac_2.", func.getParameter(2).getComment());

		func = getFunction(resultProgram, "0x00401150");
		assertEquals("Latest comment 00401150_0.", func.getParameter(0).getComment());
	}

	@Test
	public void testParamInfoConflictUseForAll() throws Exception {
		setupParamInfoConflictUseForAll();

		executeMerge(ASK_USER);
		chooseVariousOptions("0x00401150", new int[] { INFO_ROW, KEEP_MY }, true);
//		chooseVariousOptions("0x004019ac", new int[] { INFO_ROW, KEEP_MY }, false); // Handled by Use For All.
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x004019ac");
		assertEquals("My comment 004019ac_2.", func.getParameter(2).getComment());

		func = getFunction(resultProgram, "0x00401150");
		assertEquals("My comment 00401150_0.", func.getParameter(0).getComment());
	}

	@Test
	public void testParamSigConflictDontUseForAll() throws Exception {

		final Parameter[] latest_Parm1 = new Parameter[1];
		final Parameter[] latest_Parm2 = new Parameter[1];
		final Parameter[] my_count = new Parameter[1];
		final Parameter[] my_offset = new Parameter[1];

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latest_Parm1[0] =
						new MyParameter("apple", 3, new ByteDataType(), 0x14, program);
					latest_Parm2[0] =
						new MyParameter("banana", 4, new WordDataType(), 0x20, program);

					Function func = getFunction(program, "0x004019ac");
					func.setCustomVariableStorage(true);
					func.addParameter(latest_Parm1[0], SourceType.USER_DEFINED);
					func.addParameter(latest_Parm2[0], SourceType.USER_DEFINED);

					func = getFunction(program, "0x004011a0");
					func.setCustomVariableStorage(true);
					Parameter p0 = func.getParameter(0);
					p0.setName("Duck", SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					my_count[0] = new MyParameter("count", 2, new ByteDataType(), 0x14, program);
					my_offset[0] = new MyParameter("offset", 3, new WordDataType(), 0x20, program);

					Function func = getFunction(program, "0x004019ac");
					func.setCustomVariableStorage(true);
					Parameter p0 = func.getParameter(0);
					p0.setName("Mouse", SourceType.USER_DEFINED);
					Parameter p1 = func.getParameter(1);
					p1.setDataType(new FloatDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x004011a0");
					func.setCustomVariableStorage(true);
					func.addParameter(my_count[0], SourceType.USER_DEFINED);
					func.addParameter(my_offset[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		checkConflictAddress("0x004011a0");// signature @ 0x004011a0
		chooseButtonAndApply("Resolve Function Parameters Conflict", CHECKED_OUT_BUTTON_NAME,
			false);// signature @ 0x004011a0

		checkConflictAddress("0x004019ac");// signature @ 0x004019ac
		chooseButtonAndApply("Resolve Function Parameters Conflict", LATEST_BUTTON_NAME, false);// signature @ 0x004019ac

		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x004019ac");
		Parameter[] parms = func.getParameters();
		assertEquals(5, parms.length);
		assertEquals("param_1", parms[0].getName());
		assertEquals("param_2", parms[1].getName());
		assertEquals("param_3", parms[2].getName());
		assertEquals(parms[3], latest_Parm1[0]);
		assertEquals(parms[4], latest_Parm2[0]);

		func = getFunction(resultProgram, "0x004011a0");
		parms = func.getParameters();
		assertEquals(4, parms.length);
		assertEquals("list", parms[0].getName());
		assertEquals("personName", parms[1].getName());
		assertEquals(my_count[0], parms[2]);
		assertEquals(my_offset[0], parms[3]);
	}

	@Test
	public void testParamSigConflictUseForAll() throws Exception {

		final Parameter[] latest_Parm1 = new Parameter[1];
		final Parameter[] latest_Parm2 = new Parameter[1];
		final Parameter[] my_count = new Parameter[1];
		final Parameter[] my_offset = new Parameter[1];

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latest_Parm1[0] =
						new MyParameter("apple", 3, new ByteDataType(), 0x14, program);
					latest_Parm2[0] =
						new MyParameter("banana", 4, new WordDataType(), 0x20, program);

					Function func = getFunction(program, "0x004019ac");
					func.setCustomVariableStorage(true);
					func.addParameter(latest_Parm1[0], SourceType.USER_DEFINED);
					func.addParameter(latest_Parm2[0], SourceType.USER_DEFINED);

					func = getFunction(program, "0x004011a0");
					func.setCustomVariableStorage(true);
					Parameter p0 = func.getParameter(0);
					p0.setName("Duck", SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					my_count[0] = new MyParameter("count", 2, new ByteDataType(), 0x14, program);
					my_offset[0] = new MyParameter("offset", 3, new WordDataType(), 0x20, program);

					Function func = getFunction(program, "0x004019ac");
					func.setCustomVariableStorage(true);
					Parameter p0 = func.getParameter(0);
					p0.setName("Mouse", SourceType.USER_DEFINED);
					Parameter p1 = func.getParameter(1);
					p1.setDataType(new FloatDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x004011a0");
					func.setCustomVariableStorage(true);
					func.addParameter(my_count[0], SourceType.USER_DEFINED);
					func.addParameter(my_offset[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		checkConflictAddress("0x004011a0");// signature @ 0x004011a0
		chooseButtonAndApply("Resolve Function Parameters Conflict", CHECKED_OUT_BUTTON_NAME, true);// signature @ 0x004011a0

// Handled by Use For All.
//		checkConflictAddress("0x004019ac"); // signature @ 0x004019ac
//		chooseButtonAndApply("Resolve Function Parameters Conflict", LATEST_BUTTON_NAME, false); // signature @ 0x004019ac

		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x004019ac");
		Parameter[] parms = func.getParameters();
		assertEquals(3, parms.length);
		assertEquals("Mouse", parms[0].getName());
		assertEquals("param_2", parms[1].getName());
		assertTrue(new FloatDataType().isEquivalent(parms[1].getDataType()));
		assertEquals("param_3", parms[2].getName());

		func = getFunction(resultProgram, "0x004011a0");
		parms = func.getParameters();
		assertEquals(4, parms.length);
		assertEquals("list", parms[0].getName());
		assertEquals("personName", parms[1].getName());
		assertEquals(my_count[0], parms[2]);
		assertEquals(my_offset[0], parms[3]);
	}

	@Test
	public void testRemoveLocalVarConflictDontUseForAll() throws Exception {

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					function1.removeVariable(localVariables1[0]);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					((LocalVariable) localVariables2[0]).setDataType(new FloatDataType(),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					((LocalVariable) localVariables1[0]).setDataType(new DWordDataType(),
						SourceType.USER_DEFINED);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					function2.removeVariable(localVariables2[0]);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();

		executeMerge(ASK_USER);

		checkConflictAddress("0x00401150");
		chooseButtonAndApply("Resolve Function Variable Remove Conflict", CHECKED_OUT_BUTTON_NAME,
			false);

		checkConflictAddress("0x00401a58");
		chooseButtonAndApply("Resolve Function Variable Remove Conflict", LATEST_BUTTON_NAME,
			false);

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		Function function2 = getFunction(resultProgram, "0x00401a58");

		Variable[] vars1 = function1.getLocalVariables();
		assertEquals(1, vars1.length);
		assertEquals("local_8", vars1[0].getName());
		assertEquals(-8, vars1[0].getStackOffset());
		assertEquals(4, vars1[0].getLength());
		assertEquals("dword", vars1[0].getDataType().getDisplayName());
		assertTrue(new DWordDataType().isEquivalent(vars1[0].getDataType()));

		Variable[] vars2 = function2.getLocalVariables();
		assertEquals(2, vars2.length);

		assertEquals("local_8", vars2[0].getName());
		assertEquals(-0x8, vars2[0].getStackOffset());
		assertEquals(4, vars2[0].getLength());
		assertEquals("float", vars2[0].getDataType().getDisplayName());
		assertTrue(new FloatDataType().isEquivalent(vars2[0].getDataType()));

		assertEquals("local_c", vars2[1].getName());
		assertEquals(-0xc, vars2[1].getStackOffset());
		assertEquals(4, vars2[1].getLength());
		assertEquals("undefined4", vars2[1].getDataType().getDisplayName());
		assertTrue(new Undefined4DataType().isEquivalent(vars2[1].getDataType()));
	}

	@Test
	public void testRemoveLocalVarConflictUseForAll() throws Exception {

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					function1.removeVariable(localVariables1[0]);

					((LocalVariable) localVariables2[0]).setDataType(new FloatDataType(),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					((LocalVariable) localVariables1[0]).setDataType(new DWordDataType(),
						SourceType.USER_DEFINED);

					function2.removeVariable(localVariables2[0]);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();

		executeMerge(ASK_USER);

		checkConflictAddress("0x00401150");
		chooseButtonAndApply("Resolve Function Variable Remove Conflict", CHECKED_OUT_BUTTON_NAME,
			true);

// Handled by Use For All.
//		checkConflictAddress("0x00401a58");
//		chooseButtonAndApply("Resolve Function Variable Remove Conflict", CHECKED_OUT_BUTTON_NAME,
//			false);

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		Function function2 = getFunction(resultProgram, "0x00401a58");

		Variable[] vars1 = function1.getLocalVariables();
		assertEquals(1, vars1.length);
		assertEquals("local_8", vars1[0].getName());
		assertEquals(-8, vars1[0].getStackOffset());
		assertEquals(4, vars1[0].getLength());
		assertEquals("dword", vars1[0].getDataType().getDisplayName());
		assertTrue(new DWordDataType().isEquivalent(vars1[0].getDataType()));

		Variable[] vars2 = function2.getLocalVariables();
		assertEquals(1, vars2.length);
		assertEquals("local_c", vars2[0].getName());
		assertEquals(-0xc, vars2[0].getStackOffset());
		assertEquals(4, vars2[0].getLength());
		assertEquals("undefined4", vars2[0].getDataType().getDisplayName());
		assertTrue(new Undefined4DataType().isEquivalent(vars2[0].getDataType()));
	}

	@Test
	public void testLocalVarDetailConflictDontUseForAll() throws Exception {

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					localVariables1[0].setDataType(new DWordDataType(), SourceType.USER_DEFINED);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					((LocalVariable) localVariables2[0]).setDataType(new DWordDataType(),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					((LocalVariable) localVariables1[0]).setDataType(new FloatDataType(),
						SourceType.USER_DEFINED);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					localVariables2[0].setDataType(new FloatDataType(), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve Function Local Variable Conflict",
			VariousChoicesPanel.class);
		chooseVariousOptions("0x00401150", new int[] { INFO_ROW, KEEP_MY }, false);

		checkConflictPanelTitle("Resolve Function Local Variable Conflict",
			VariousChoicesPanel.class);
		chooseVariousOptions("0x00401a58", new int[] { INFO_ROW, KEEP_LATEST }, false);

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		Variable[] vars1 = function1.getLocalVariables();
		assertEquals(1, vars1.length);
		assertEquals("local_8", vars1[0].getName());
		assertEquals(-8, vars1[0].getStackOffset());
		assertEquals(4, vars1[0].getLength());
		assertEquals("float", vars1[0].getDataType().getDisplayName());
		assertTrue(new FloatDataType().isEquivalent(vars1[0].getDataType()));

		Function function2 = getFunction(resultProgram, "0x00401a58");
		Variable[] vars2 = function2.getLocalVariables();
		assertEquals(2, vars2.length);

		assertEquals("local_8", vars2[0].getName());
		assertEquals(-0x8, vars2[0].getStackOffset());
		assertEquals(4, vars2[0].getLength());
		assertEquals("dword", vars2[0].getDataType().getDisplayName());
		assertTrue(new DWordDataType().isEquivalent(vars2[0].getDataType()));

		assertEquals("local_c", vars2[1].getName());
		assertEquals(-0xc, vars2[1].getStackOffset());
		assertEquals(4, vars2[1].getLength());
		assertEquals("undefined4", vars2[1].getDataType().getDisplayName());
		assertTrue(new Undefined4DataType().isEquivalent(vars2[1].getDataType()));
	}

	@Test
	public void testLocalVarDetailConflictUseForAll() throws Exception {

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					localVariables1[0].setDataType(new DWordDataType(), SourceType.USER_DEFINED);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					((LocalVariable) localVariables2[0]).setDataType(new DWordDataType(),
						SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// undefined4 local_8
					Function function1 = getFunction(program, "0x00401150");
					Variable[] localVariables1 = function1.getLocalVariables();
					assertEquals(1, localVariables1.length);

					((LocalVariable) localVariables1[0]).setDataType(new FloatDataType(),
						SourceType.USER_DEFINED);

					// undefined4 local_8
					// undefined4 local_c
					Function function2 = getFunction(program, "0x00401a58");
					Variable[] localVariables2 = function2.getLocalVariables();
					assertEquals(2, localVariables2.length);

					localVariables2[0].setDataType(new FloatDataType(), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve Function Local Variable Conflict",
			VariousChoicesPanel.class);
		chooseVariousOptions("0x00401150", new int[] { INFO_ROW, KEEP_MY }, true);

// Handled by Use For All.
//		checkConflictPanelTitle("Resolve Function Local Variable Conflict",
//			VariousChoicesPanel.class);
//		chooseVariousOptions("0x00401a58", new int[] { INFO_ROW, KEEP_MY }, false);

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		Variable[] vars1 = function1.getLocalVariables();
		assertEquals(1, vars1.length);
		assertEquals("local_8", vars1[0].getName());
		assertEquals(-8, vars1[0].getStackOffset());
		assertEquals(4, vars1[0].getLength());
		assertEquals("float", vars1[0].getDataType().getDisplayName());
		assertTrue(new FloatDataType().isEquivalent(vars1[0].getDataType()));

		Function function2 = getFunction(resultProgram, "0x00401a58");
		Variable[] vars2 = function2.getLocalVariables();
		assertEquals(2, vars2.length);

		assertEquals("local_8", vars2[0].getName());
		assertEquals(-0x8, vars2[0].getStackOffset());
		assertEquals(4, vars2[0].getLength());
		assertEquals("float", vars2[0].getDataType().getDisplayName());
		assertTrue(new FloatDataType().isEquivalent(vars2[0].getDataType()));

		assertEquals("local_c", vars2[1].getName());
		assertEquals(-0xc, vars2[1].getStackOffset());
		assertEquals(4, vars2[1].getLength());
		assertEquals("undefined4", vars2[1].getDataType().getDisplayName());
		assertTrue(new Undefined4DataType().isEquivalent(vars2[1].getDataType()));
	}

	@Test
	public void testFunctionDetailConflictDontUseForAll() throws Exception {

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");// Initially __stdcall
					function1.setCallingConvention("__cdecl");// change to __cdecl

					Function function2 = getFunction(program, "0x00401a58");// Initially __cdecl
					function2.setCallingConvention("__fastcall");// Change to __fastcall

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");// Initially __stdcall
					function1.setCallingConvention("__fastcall");// change to __fastcall

					Function function2 = getFunction(program, "0x00401a58");// Initially __cdecl
					function2.setCallingConvention("__stdcall");// Change to __stdcall

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve Function Conflict", VariousChoicesPanel.class);
		chooseVariousOptions("0x00401150", new int[] { INFO_ROW, KEEP_MY }, false);

		checkConflictPanelTitle("Resolve Function Conflict", VariousChoicesPanel.class);
		chooseVariousOptions("0x00401a58", new int[] { INFO_ROW, KEEP_LATEST }, false);

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		assertEquals("__fastcall", function1.getCallingConventionName());

		Function function2 = getFunction(resultProgram, "0x00401a58");
		assertEquals("__fastcall", function2.getCallingConventionName());
	}

	@Test
	public void testFunctionDetailConflictUseForAll() throws Exception {

		mtf.initialize("WallaceSrc", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");// Initially __stdcall
					function1.setCallingConvention("__cdecl");// change to __cdecl

					Function function2 = getFunction(program, "0x00401a58");// Initially __cdecl
					function2.setCallingConvention("__fastcall");// Change to __fastcall

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function1 = getFunction(program, "0x00401150");// Initially __stdcall
					function1.setCallingConvention("__fastcall");// change to __fastcall

					Function function2 = getFunction(program, "0x00401a58");// Initially __cdecl
					function2.setCallingConvention("__stdcall");// Change to __stdcall

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve Function Conflict", VariousChoicesPanel.class);
		chooseVariousOptions("0x00401150", new int[] { INFO_ROW, KEEP_MY }, true);

// Handled by Use For All.
//		checkConflictPanelTitle("Resolve Function Conflict", VariousChoicesPanel.class);
//		chooseVariousOptions("0x00401a58", new int[] { INFO_ROW, KEEP_MY }, false);

		waitForMergeCompletion();

		Function function1 = getFunction(resultProgram, "0x00401150");
		assertEquals("__fastcall", function1.getCallingConventionName());

		Function function2 = getFunction(resultProgram, "0x00401a58");
		assertEquals("__stdcall", function2.getCallingConventionName());
	}

	protected void checkConflictAddress(final String addrStr) throws Exception {
		waitForPrompting();
		Window window = windowForComponent(getMergePanel());
		ConflictInfoPanel infoComp = findComponent(window, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		Address addr = addr(addrStr);
		assertEquals(addr.toString(), infoComp.getAddress().toString());
	}
}
