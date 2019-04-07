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
package ghidra.app.cmd.data.exceptionhandling;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.cmd.data.CreateTypeDescriptorBackgroundCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

public class EH64CreateCmdTest extends AbstractEHTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = build64BitX86();
		program = builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		preserveDTMService(program);
		if (builder != null) {
			builder.dispose();
			builder = null;
		}
	}

	@Test
	public void testValidV1FuncInfo64Cmd() throws Exception {
		setupV1FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v1FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV1Data64(program, 0x101003340L);
	}

	@Test
	public void testValidV2FuncInfo64Cmd() throws Exception {
		setupV2FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v2FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v2FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV2Data64(program, 0x101003340L);
	}

	@Test
	public void testValidV3FuncInfo64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v1FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV3Data64(program, 0x101003340L);
	}

	@Test
	public void testValidUnwindMap64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHUnwindMapBackgroundCmd unwindMapCmd = new CreateEHUnwindMapBackgroundCmd(
			addr(program, 0x101003368L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = unwindMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkUnwindMapData64(program, 0x101003368L);
	}

	@Test
	public void testValidTryBlockMap64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHTryBlockMapBackgroundCmd tryBlockMapCmd = new CreateEHTryBlockMapBackgroundCmd(
			addr(program, 0x101003380L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = tryBlockMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkTryBlockData64(program, 0x101003380L);
	}

	@Test
	public void testValidCatchHandlerMap64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHCatchHandlerMapBackgroundCmd catchHandlerMapCmd =
			new CreateEHCatchHandlerMapBackgroundCmd(addr(program, 0x1010033a8L), 1,
				defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = catchHandlerMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkCatchHandlerData64(program, 0x1010033a8L);
	}

	@Test
	public void testValidTypeDescriptor64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateTypeDescriptorBackgroundCmd typeDescriptorCmd = new CreateTypeDescriptorBackgroundCmd(
			addr(program, 0x101005400L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = typeDescriptorCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkTypeDescriptorData(program, 0x101005400L, 16, 24, "NotReachableError");
	}

	@Test
	public void testValidIPToStateMap64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHIPToStateMapBackgroundCmd ipToStateMapCmd = new CreateEHIPToStateMapBackgroundCmd(
			addr(program, 0x1010033d0L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = ipToStateMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkIPToStateMapData64(program, 0x1010033d0L);
	}

	@Test
	public void testValidESTypeList64Cmd() throws Exception {
		setupV3FuncInfo64CompleteFlow(builder);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHESTypeListBackgroundCmd esTypeListCmd = new CreateEHESTypeListBackgroundCmd(
			addr(program, 0x1010033f0L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = esTypeListCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkESTypeListData64(program, 0x1010033f0L);
	}

	@Test
	public void testValidV1FuncInfo64CmdNoFollow() throws Exception {
		setupV1FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v1FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV1Data64(program, 0x101003340L);
	}

	@Test
	public void testValidV2FuncInfo64CmdNoFollow() throws Exception {
		setupV2FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0");
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v2FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v2FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV2Data64(program, 0x101003340L);
	}

	@Test
	public void testValidV3FuncInfo64CmdNoFollow() throws Exception {
		setupV3FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0", 0x1);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v1FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV3Data64(program, 0x101003340L);
	}

	@Test
	public void testValidUnwindMap64CmdNoFollow() throws Exception {
		setupUnwind64(builder, 0x01001640, 0xFFFFFFFF, "0x01001360");
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHUnwindMapBackgroundCmd unwindMapCmd = new CreateEHUnwindMapBackgroundCmd(
			addr(program, 0x101001640L), 1, noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = unwindMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkUnwindMapData64(program, 0x101001640L);
	}

	@Test
	public void testValidTryBlockMap64CmdNoFollow() throws Exception {
		setupTryBlock64(builder, 0x01001340, 0, 2, 3, 1, "0x01001380");
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHTryBlockMapBackgroundCmd tryBlockMapCmd = new CreateEHTryBlockMapBackgroundCmd(
			addr(program, 0x101001340L), 1, noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = tryBlockMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkTryBlockData64(program, 0x101001340L);
	}

	@Test
	public void testValidCatchHandlerMap64CmdNoFollow() throws Exception {
		setupCatchHandler64(builder, 0x1010033a8L, 0x3, "0x101005400", 5, "0x101001260", 0x58); // 20 bytes
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHCatchHandlerMapBackgroundCmd catchHandlerMapCmd =
			new CreateEHCatchHandlerMapBackgroundCmd(addr(program, 0x1010033a8L), 1,
				noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = catchHandlerMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkCatchHandlerData64(program, 0x1010033a8L);
	}

	@Test
	public void testValidIPToStateMap64CmdNoFollow() throws Exception {
		setupIPToState64(builder, 0x01001340, "0x01001364", -1);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHIPToStateMapBackgroundCmd ipToStateMapCmd = new CreateEHIPToStateMapBackgroundCmd(
			addr(program, 0x101001340L), 1, noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = ipToStateMapCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkIPToStateMapData64(program, 0x101001340L);
	}

	@Test
	public void testValidESTypeList64CmdNoFollow() throws Exception {
		setupTypeList64(builder, 0x101001340L, 1, "0x01001364");
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHESTypeListBackgroundCmd esTypeListCmd = new CreateEHESTypeListBackgroundCmd(
			addr(program, 0x101001340L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = esTypeListCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkESTypeListData64(program, 0x101001340L);
	}

	@Test
	public void testValidV1FuncInfo64CmdFollow() throws Exception {
		setupV1FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v1FuncInfoCmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkFuncInfoV1Data64(program, 0x101003340L);
	}

	@Test
	public void testInvalidV2FuncInfo64CmdFollow() throws Exception {
		setupV2FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0");
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v2FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v2FuncInfoCmd.applyTo(program);
			assertFalse(applied); // Don't allow ESTypeList to be empty/null.
			commit = false;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		checkNoData(program, 0x101003340L);
	}

	@Test
	public void testInvalidV3FuncInfo64CmdFollow() throws Exception {
		setupV3FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0", 0x1);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x101003340L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = v1FuncInfoCmd.applyTo(program);
			assertFalse(applied); // Don't allow ESTypeList to be empty/null.
			commit = false;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		checkNoData(program, 0x101003340L);
	}

	@Test
	public void testValidUnwindMap64CmdFollow() throws Exception {
		setupUnwind64(builder, 0x101003368L, 0xffffffff, "0x101001200"); // 8 bytes
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHUnwindMapBackgroundCmd unwindMapCmd = new CreateEHUnwindMapBackgroundCmd(
			addr(program, 0x101003368L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = unwindMapCmd.applyTo(program);
			assertTrue(applied); // No data created by following.
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkUnwindMapData64(program, 0x101003368L);
	}

	@Test
	public void testInvalidTryBlockMap64CmdFollow() throws Exception {
		setupTryBlock64(builder, 0x101003380L, 2, 2, 3, 2, "0x1010033a8"); // 20 bytes
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHTryBlockMapBackgroundCmd tryBlockMapCmd = new CreateEHTryBlockMapBackgroundCmd(
			addr(program, 0x101003380L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = tryBlockMapCmd.applyTo(program);
			assertFalse(applied);
			commit = false;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		checkNoData(program, 0x101003380L);
	}

	@Test
	public void testInvalidCatchHandlerMap64CmdFollow() throws Exception {
		setupCatchHandler64(builder, 0x1010033a8L, 0x3, "0x101005400", 5, "0x101001260", 0x58); // 20 bytes
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHCatchHandlerMapBackgroundCmd catchHandlerMapCmd =
			new CreateEHCatchHandlerMapBackgroundCmd(addr(program, 0x1010033a8L), 1,
				defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = catchHandlerMapCmd.applyTo(program);
			assertFalse(applied);
			commit = false;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		checkNoData(program, 0x1010033a8L);
	}

	@Test
	public void testValidIPToStateMap64CmdFollow() throws Exception {
		setupIPToState64(builder, 0x1010033d0L, "0x101001200", -1);
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHIPToStateMapBackgroundCmd ipToStateMapCmd = new CreateEHIPToStateMapBackgroundCmd(
			addr(program, 0x1010033d0L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = ipToStateMapCmd.applyTo(program);
			assertTrue(applied); // No data created by following.
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		// Now check data is created with the correct structure.
		checkIPToStateMapData64(program, 0x1010033d0L);
	}

	@Test
	public void testInvalidESTypeList64CmdFollow() throws Exception {
		setupTypeList64(builder, 0x1010033f0L, 1, "0x101001800");
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		CreateEHESTypeListBackgroundCmd esTypeListCmd = new CreateEHESTypeListBackgroundCmd(
			addr(program, 0x1010033f0L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating EH data");
		boolean commit = false;
		try {
			boolean applied = esTypeListCmd.applyTo(program);
			assertFalse(applied);
			commit = false;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		checkNoData(program, 0x1010033f0L);
	}
}
