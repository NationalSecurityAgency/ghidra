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

public class EH32CreateCmdTest extends AbstractEHTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = build32BitX86();
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
	public void testValidV1FuncInfo32Cmd() throws Exception {
		setupV1FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01003340), defaultValidationOptions, defaultApplyOptions);

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
		checkFuncInfoV1Data(program, 0x01003340L);
	}

	@Test
	public void testValidV2FuncInfo32Cmd() throws Exception {
		setupV2FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v2FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01003340), defaultValidationOptions, defaultApplyOptions);

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
		checkFuncInfoV2Data(program, 0x01003340L);
	}

	@Test
	public void testValidV3FuncInfo32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01003340), defaultValidationOptions, defaultApplyOptions);

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
		checkFuncInfoV3Data(program, 0x01003340L);
	}

	@Test
	public void testValidUnwindMap32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHUnwindMapBackgroundCmd unwindMapCmd = new CreateEHUnwindMapBackgroundCmd(
			addr(program, 0x01003368), 1, defaultValidationOptions, defaultApplyOptions);

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
		checkUnwindMapData32(program, 0x01003368);
	}

	@Test
	public void testValidTryBlockMap32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHTryBlockMapBackgroundCmd tryBlockMapCmd = new CreateEHTryBlockMapBackgroundCmd(
			addr(program, 0x01003380), 1, defaultValidationOptions, defaultApplyOptions);

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
		checkTryBlockData32(program, 0x01003380);
	}

	@Test
	public void testValidCatchHandlerMap32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHCatchHandlerMapBackgroundCmd catchHandlerMapCmd =
			new CreateEHCatchHandlerMapBackgroundCmd(addr(program, 0x010033a8), 1,
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
		checkCatchHandlerData32(program, 0x010033a8);
	}

	@Test
	public void testValidTypeDescriptor32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateTypeDescriptorBackgroundCmd typeDescriptorCmd = new CreateTypeDescriptorBackgroundCmd(
			addr(program, 0x01005400), defaultValidationOptions, defaultApplyOptions);

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
		checkTypeDescriptorData(program, 0x01005400, 8, 20, "NotReachableError");
	}

	@Test
	public void testValidIPToStateMap32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHIPToStateMapBackgroundCmd ipToStateMapCmd = new CreateEHIPToStateMapBackgroundCmd(
			addr(program, 0x010033d0), 1, defaultValidationOptions, defaultApplyOptions);

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
		checkIPToStateMapData32(program, 0x010033d0);
	}

	@Test
	public void testValidESTypeList32Cmd() throws Exception {
		setupV3FuncInfo32CompleteFlow(builder);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHESTypeListBackgroundCmd esTypeListCmd = new CreateEHESTypeListBackgroundCmd(
			addr(program, 0x010033f0), defaultValidationOptions, defaultApplyOptions);

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
		checkESTypeListData32(program, 0x010033f0);
	}

	@Test
	public void testValidV1FuncInfo32CmdNoFollow() throws Exception {
		setupV1FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01001340), noFollowValidationOptions, noFollowApplyOptions);

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
		checkFuncInfoV1Data(program, 0x01001340L);
	}

	@Test
	public void testValidV2FuncInfo32CmdNoFollow() throws Exception {
		setupV2FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v2FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01001340), noFollowValidationOptions, noFollowApplyOptions);

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
		checkFuncInfoV2Data(program, 0x01001340L);
	}

	@Test
	public void testValidV3FuncInfo32CmdNoFollow() throws Exception {
		setupV3FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388", 0x1);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01001340), noFollowValidationOptions, noFollowApplyOptions);

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
		checkFuncInfoV3Data(program, 0x01001340L);
	}

	@Test
	public void testValidUnwindMap32CmdNoFollow() throws Exception {
		setupUnwind32(builder, 0x01001320, 0xFFFFFFFF, "0x01001360");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHUnwindMapBackgroundCmd unwindMapCmd = new CreateEHUnwindMapBackgroundCmd(
			addr(program, 0x01001320), 1, noFollowValidationOptions, noFollowApplyOptions);

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
		checkUnwindMapData32(program, 0x01001320L);
	}

	@Test
	public void testValidTryBlockMap32CmdNoFollow() throws Exception {
		setupTryBlock32(builder, 0x01001340, 0, 2, 3, 1, "0x01001380");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHTryBlockMapBackgroundCmd tryBlockMapCmd = new CreateEHTryBlockMapBackgroundCmd(
			addr(program, 0x01001340), 1, noFollowValidationOptions, noFollowApplyOptions);

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
		checkTryBlockData32(program, 0x01001340L);
	}

	@Test
	public void testValidCatchHandlerMap32CmdNoFollow() throws Exception {
		setupCatchHandler32(builder, 0x01001340, 1, "0x01005360", 0, "0x01001400");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHCatchHandlerMapBackgroundCmd catchHandlerMapCmd =
			new CreateEHCatchHandlerMapBackgroundCmd(addr(program, 0x01001340), 1,
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
		checkCatchHandlerData32(program, 0x01001340L);
	}

	@Test
	public void testValidIPToStateMap32CmdNoFollow() throws Exception {
		setupIPToState32(builder, 0x01001340, 0x01001364, -1);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHIPToStateMapBackgroundCmd ipToStateMapCmd = new CreateEHIPToStateMapBackgroundCmd(
			addr(program, 0x01001340), 1, noFollowValidationOptions, noFollowApplyOptions);

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
		checkIPToStateMapData32(program, 0x01001340L);
	}

	@Test
	public void testValidESTypeList32CmdNoFollow() throws Exception {
		setupTypeList32(builder, 0x01001340, 1, "0x01001364");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHESTypeListBackgroundCmd esTypeListCmd = new CreateEHESTypeListBackgroundCmd(
			addr(program, 0x01001340), noFollowValidationOptions, noFollowApplyOptions);

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
		checkESTypeListData32(program, 0x01001340L);
	}

	@Test
	public void testValidV1FuncInfo32CmdFollow() throws Exception {
		setupV1FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01001340), defaultValidationOptions, defaultApplyOptions);

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
		checkFuncInfoV1Data(program, 0x01001340L);
	}

	@Test
	public void testInvalidV2FuncInfo32CmdFollow() throws Exception {
		setupV2FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v2FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01001340), defaultValidationOptions, defaultApplyOptions);

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

		checkNoData(program, 0x01001340L);
	}

	@Test
	public void testInvalidV3FuncInfo32CmdFollow() throws Exception {
		setupV3FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388", 0x1);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHFuncInfoBackgroundCmd v1FuncInfoCmd = new CreateEHFuncInfoBackgroundCmd(
			addr(program, 0x01001340), defaultValidationOptions, defaultApplyOptions);

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

		checkNoData(program, 0x01001340L);
	}

	@Test
	public void testValidUnwindMap32CmdFollow() throws Exception {
		setupUnwind32(builder, 0x01001320, 0xFFFFFFFF, "0x01001360");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHUnwindMapBackgroundCmd unwindMapCmd = new CreateEHUnwindMapBackgroundCmd(
			addr(program, 0x01001320), 1, defaultValidationOptions, defaultApplyOptions);

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
		checkUnwindMapData32(program, 0x01001320L);
	}

	@Test
	public void testInvalidTryBlockMap32CmdFollow() throws Exception {
		setupTryBlock32(builder, 0x01001340, 0, 2, 3, 1, "0x01001380");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHTryBlockMapBackgroundCmd tryBlockMapCmd = new CreateEHTryBlockMapBackgroundCmd(
			addr(program, 0x01001340), 1, defaultValidationOptions, defaultApplyOptions);

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

		checkNoData(program, 0x01001340L);
	}

	@Test
	public void testInvalidCatchHandlerMap32CmdFollow() throws Exception {
		setupCatchHandler32(builder, 0x01001340, 1, "0x01001360", 0, "0x01001400");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHCatchHandlerMapBackgroundCmd catchHandlerMapCmd =
			new CreateEHCatchHandlerMapBackgroundCmd(addr(program, 0x01001340), 1,
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

		checkNoData(program, 0x01001340L);
	}

	@Test
	public void testValidIPToStateMap32CmdFollow() throws Exception {
		setupIPToState32(builder, 0x01001340, 0x01001364, -1);
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHIPToStateMapBackgroundCmd ipToStateMapCmd = new CreateEHIPToStateMapBackgroundCmd(
			addr(program, 0x01001340), 1, defaultValidationOptions, defaultApplyOptions);

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
		checkIPToStateMapData32(program, 0x01001340L);
	}

	@Test
	public void testInvalidESTypeList32CmdFollow() throws Exception {
		setupTypeList32(builder, 0x01001340, 1, "0x01001364");
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		CreateEHESTypeListBackgroundCmd esTypeListCmd = new CreateEHESTypeListBackgroundCmd(
			addr(program, 0x01001340), defaultValidationOptions, defaultApplyOptions);

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

		checkNoData(program, 0x01001340L);
	}
}
