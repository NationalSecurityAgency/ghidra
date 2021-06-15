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
package ghidra.app.cmd.data.rtti;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.app.cmd.data.CreateTypeDescriptorBackgroundCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.task.TaskMonitor;

public class RttiCreateCmdTest extends AbstractRttiTest {

	@Test
	public void testValidRtti4Cmd_32CompleteFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		List<MemoryBlock> rtti4Blocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".rdata", TaskMonitor.DUMMY);

		CreateRtti4BackgroundCmd rtti4Cmd = new CreateRtti4BackgroundCmd(addr(program, 0x01003340L),
			rtti4Blocks, defaultValidationOptions, defaultApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd2 = new CreateRtti4BackgroundCmd(
			addr(program, 0x01003354L), rtti4Blocks, defaultValidationOptions, defaultApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd3 = new CreateRtti4BackgroundCmd(
			addr(program, 0x01003240L), rtti4Blocks, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti4Cmd.applyTo(program);
			assertTrue(applied);

			boolean applied2 = rtti4Cmd2.applyTo(program);
			assertTrue(applied2);

			boolean applied3 = rtti4Cmd3.applyTo(program);
			assertTrue(applied3);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4Data(program, 0x01003340L);
		checkRtti3Data(program, 0x01003368L);
		checkRtti2Data(program, 0x01003390L, 1);
		checkRtti1Data(program, 0x010033a8L);
		checkTypeDescriptorData(program, 0x01005200L, 8, 12, ".?AVBase@@");
		checkVfTableData(program, 0x010032f0L, 0x01003340L, 0x010032f4L,
			new long[] { 0x01001200L, 0x01001280L });

		// ---- check Shape ----
		checkRtti4Data(program, 0x01003354L);
		checkRtti3Data(program, 0x01003378L);
		checkRtti2Data(program, 0x01003394L, 2);
		checkRtti1Data(program, 0x010033c4L);
		checkTypeDescriptorData(program, 0x01005214L, 8, 12, ".?AVShape@@");
		checkVfTableData(program, 0x01003230L, 0x01003354L, 0x01003234L,
			new long[] { 0x01001214L, 0x01001230L });

		// ---- check Circle ----
		checkRtti4Data(program, 0x01003240L);
		checkRtti3Data(program, 0x01003268L);
		checkRtti2Data(program, 0x01003290L, 3);
		checkRtti1Data(program, 0x010032a8L);
		checkTypeDescriptorData(program, 0x010053e0L, 8, 16, ".?AVCircle@@");
		checkVfTableData(program, 0x010031f0, 0x01003240L, 0x010031f4L,
			new long[] { 0x01001260L, 0x010012a0L });
	}

	@Test
	public void testValidRtti3Cmd_32FollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateRtti3BackgroundCmd rtti3Cmd = new CreateRtti3BackgroundCmd(addr(program, 0x01003368L),
			defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti3Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkRtti3Data(program, 0x01003368L);
		checkRtti2Data(program, 0x01003390L, 1);
		checkRtti1Data(program, 0x010033a8L);
		checkTypeDescriptorData(program, 0x01005200L, 8, 12, ".?AVBase@@");
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti2Cmd_32FollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateRtti2BackgroundCmd rtti2Cmd = new CreateRtti2BackgroundCmd(addr(program, 0x01003390L),
			1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti2Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkRtti3Data(program, 0x01003368L);
		checkRtti2Data(program, 0x01003390L, 1);
		checkRtti1Data(program, 0x010033a8L);
		checkTypeDescriptorData(program, 0x01005200L, 8, 12, ".?AVBase@@");
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti1Cmd_32FollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateRtti1BackgroundCmd rtti1Cmd = new CreateRtti1BackgroundCmd(addr(program, 0x010033a8L),
			defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti1Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkRtti3Data(program, 0x01003368L);
		checkRtti2Data(program, 0x01003390L, 1);
		checkRtti1Data(program, 0x010033a8L);
		checkTypeDescriptorData(program, 0x01005200L, 8, 12, ".?AVBase@@");
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti0Cmd_32FollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateTypeDescriptorBackgroundCmd rtti0Cmd = new CreateTypeDescriptorBackgroundCmd(
			addr(program, 0x01005200L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti0Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkNoData(program, 0x01003368L);
		checkNoData(program, 0x01003390L);
		checkNoData(program, 0x010033a8L);
		checkTypeDescriptorData(program, 0x01005200L, 8, 16, ".?AVBase@@");
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti4Cmd_64CompleteFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		List<MemoryBlock> rtti4Blocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".rdata", TaskMonitor.DUMMY);

		CreateRtti4BackgroundCmd rtti4Cmd =
			new CreateRtti4BackgroundCmd(addr(program, 0x101003340L), rtti4Blocks,
				defaultValidationOptions, defaultApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd2 =
			new CreateRtti4BackgroundCmd(addr(program, 0x101003354L), rtti4Blocks,
				defaultValidationOptions, defaultApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd3 =
			new CreateRtti4BackgroundCmd(addr(program, 0x10100324cL), rtti4Blocks,
				defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti4Cmd.applyTo(program);
			assertTrue(applied);

			boolean applied2 = rtti4Cmd2.applyTo(program);
			assertTrue(applied2);

			boolean applied3 = rtti4Cmd3.applyTo(program);
			assertTrue(applied3);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4Data(program, 0x101003340L);
		checkRtti3Data(program, 0x101003368L);
		checkRtti2Data(program, 0x101003390L, 1);
		checkRtti1Data(program, 0x1010033a8L);
		checkTypeDescriptorData(program, 0x101005200L, 16, 16, ".?AVBase@@");
		checkVfTableData(program, 0x1010032f0L, 0x101003340L, 0x1010032f8L,
			new long[] { 0x101001200L, 0x101001280L });

		// ---- check Shape ----
		checkRtti4Data(program, 0x101003354L);
		checkRtti3Data(program, 0x101003378L);
		checkRtti2Data(program, 0x101003394L, 2);
		checkRtti1Data(program, 0x1010033c4L);
		checkTypeDescriptorData(program, 0x101005220L, 16, 16, ".?AVShape@@");
		checkVfTableData(program, 0x1010031b0L, 0x101003354L, 0x1010031b8L,
			new long[] { 0x101001214L, 0x101001230L });

		// ---- check Circle ----
		checkRtti4Data(program, 0x10100324cL);
		checkRtti3Data(program, 0x101003268L);
		checkRtti2Data(program, 0x101003290L, 3);
		checkRtti1Data(program, 0x1010032a8L);
		checkTypeDescriptorData(program, 0x1010053e0L, 16, 16, ".?AVCircle@@");
		checkVfTableData(program, 0x1010031d0L, 0x10100324cL, 0x1010031d8L,
			new long[] { 0x101001260L, 0x1010012a0L, 0x101001120L });

	}

	@Test
	public void testValidRtti3Cmd_64FollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateRtti3BackgroundCmd rtti3Cmd = new CreateRtti3BackgroundCmd(
			addr(program, 0x101003368L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti3Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkRtti3Data(program, 0x101003368L);
		checkRtti2Data(program, 0x101003390L, 1);
		checkRtti1Data(program, 0x1010033a8L);
		checkTypeDescriptorData(program, 0x101005200L, 16, 16, ".?AVBase@@");
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti2Cmd_64FollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateRtti2BackgroundCmd rtti2Cmd = new CreateRtti2BackgroundCmd(
			addr(program, 0x101003390L), 1, defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti2Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkRtti3Data(program, 0x101003368L);
		checkRtti2Data(program, 0x101003390L, 1);
		checkRtti1Data(program, 0x1010033a8L);
		checkTypeDescriptorData(program, 0x101005200L, 16, 16, ".?AVBase@@");
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti1Cmd_64FollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateRtti1BackgroundCmd rtti1Cmd = new CreateRtti1BackgroundCmd(
			addr(program, 0x1010033a8L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti1Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkRtti3Data(program, 0x101003368L);
		checkRtti2Data(program, 0x101003390L, 1);
		checkRtti1Data(program, 0x1010033a8L);
		checkTypeDescriptorData(program, 0x101005200L, 16, 16, ".?AVBase@@");
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti0Cmd_64FollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateTypeDescriptorBackgroundCmd rtti0Cmd = new CreateTypeDescriptorBackgroundCmd(
			addr(program, 0x101005200L), defaultValidationOptions, defaultApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti0Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkNoData(program, 0x101003368L);
		checkNoData(program, 0x101003390L);
		checkNoData(program, 0x1010033a8L);
		checkTypeDescriptorData(program, 0x101005200L, 16, 16, ".?AVBase@@");
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti4Cmd_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		List<MemoryBlock> rtti4Blocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".rdata", TaskMonitor.DUMMY);

		CreateRtti4BackgroundCmd rtti4Cmd = new CreateRtti4BackgroundCmd(addr(program, 0x01003340L),
			rtti4Blocks, noFollowValidationOptions, noFollowApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd2 =
			new CreateRtti4BackgroundCmd(addr(program, 0x01003354L), rtti4Blocks,
				noFollowValidationOptions, noFollowApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd3 =
			new CreateRtti4BackgroundCmd(addr(program, 0x01003240L), rtti4Blocks,
				noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti4Cmd.applyTo(program);
			assertTrue(applied);

			boolean applied2 = rtti4Cmd2.applyTo(program);
			assertTrue(applied2);

			boolean applied3 = rtti4Cmd3.applyTo(program);
			assertTrue(applied3);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4Data(program, 0x01003340L);
		checkNoData(program, 0x01003368L);
		checkNoData(program, 0x01003390L);
		checkNoData(program, 0x010033a8L);
		checkNoData(program, 0x01003200L);
		checkNoData(program, 0x010032f0L);

		// ---- check Shape ----
		checkRtti4Data(program, 0x01003354L);
		checkNoData(program, 0x01003378L);
		checkNoData(program, 0x01003394L);
		checkNoData(program, 0x010033c4L);
		checkNoData(program, 0x01003214L);
		checkNoData(program, 0x01003230L);

		// ---- check Circle ----
		checkRtti4Data(program, 0x01003240L);
		checkNoData(program, 0x01003268L);
		checkNoData(program, 0x01003290L);
		checkNoData(program, 0x010032a8L);
		checkNoData(program, 0x010033e0L);
		checkNoData(program, 0x010031f0);
	}

	@Test
	public void testValidRtti3Cmd_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateRtti3BackgroundCmd rtti3Cmd = new CreateRtti3BackgroundCmd(addr(program, 0x01003368L),
			noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti3Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkRtti3Data(program, 0x01003368L);
		checkNoData(program, 0x01003390L);
		checkNoData(program, 0x010033a8L);
		checkNoData(program, 0x01003200L);
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti2Cmd_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateRtti2BackgroundCmd rtti2Cmd = new CreateRtti2BackgroundCmd(addr(program, 0x01003390L),
			1, noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti2Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkNoData(program, 0x01003368L);
		checkRtti2Data(program, 0x01003390L, 1);
		checkNoData(program, 0x010033a8L);
		checkNoData(program, 0x01003200L);
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti1Cmd_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateRtti1BackgroundCmd rtti1Cmd = new CreateRtti1BackgroundCmd(addr(program, 0x010033a8L),
			noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti1Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkNoData(program, 0x01003368L);
		checkNoData(program, 0x01003390L);
		checkRtti1Data(program, 0x010033a8L);
		checkNoData(program, 0x01003200L);
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti0Cmd_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		CreateTypeDescriptorBackgroundCmd rtti0Cmd = new CreateTypeDescriptorBackgroundCmd(
			addr(program, 0x01005200L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti0Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x01003340L);
		checkNoData(program, 0x01003368L);
		checkNoData(program, 0x01003390L);
		checkNoData(program, 0x010033a8L);
		checkTypeDescriptorData(program, 0x01005200L, 8, 12, ".?AVBase@@");
		checkNoData(program, 0x010032f0L);
	}

	@Test
	public void testValidRtti4Cmd_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		List<MemoryBlock> rtti4Blocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".rdata", TaskMonitor.DUMMY);

		CreateRtti4BackgroundCmd rtti4Cmd =
			new CreateRtti4BackgroundCmd(addr(program, 0x101003340L), rtti4Blocks,
				noFollowValidationOptions, noFollowApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd2 =
			new CreateRtti4BackgroundCmd(addr(program, 0x101003354L), rtti4Blocks,
				noFollowValidationOptions, noFollowApplyOptions);

		CreateRtti4BackgroundCmd rtti4Cmd3 =
			new CreateRtti4BackgroundCmd(addr(program, 0x10100324cL), rtti4Blocks,
				noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti4Cmd.applyTo(program);
			assertTrue(applied);

			boolean applied2 = rtti4Cmd2.applyTo(program);
			assertTrue(applied2);

			boolean applied3 = rtti4Cmd3.applyTo(program);
			assertTrue(applied3);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4Data(program, 0x101003340L);
		checkNoData(program, 0x101003368L);
		checkNoData(program, 0x101003390L);
		checkNoData(program, 0x1010033a8L);
		checkNoData(program, 0x101003200L);
		checkNoData(program, 0x1010032f0L);

		// ---- check Shape ----
		checkRtti4Data(program, 0x101003354L);
		checkNoData(program, 0x101003378L);
		checkNoData(program, 0x101003394L);
		checkNoData(program, 0x1010033c4L);
		checkNoData(program, 0x101003220L);
		checkNoData(program, 0x1010031b0L);

		// ---- check Circle ----
		checkRtti4Data(program, 0x10100324cL);
		checkNoData(program, 0x101003268L);
		checkNoData(program, 0x101003290L);
		checkNoData(program, 0x1010032a8L);
		checkNoData(program, 0x1010033e0L);
		checkNoData(program, 0x1010031d0L);

	}

	@Test
	public void testValidRtti3Cmd_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateRtti3BackgroundCmd rtti3Cmd = new CreateRtti3BackgroundCmd(
			addr(program, 0x101003368L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti3Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkRtti3Data(program, 0x101003368L);
		checkNoData(program, 0x101003390L);
		checkNoData(program, 0x1010033a8L);
		checkNoData(program, 0x101003200L);
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti2Cmd_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateRtti2BackgroundCmd rtti2Cmd = new CreateRtti2BackgroundCmd(
			addr(program, 0x101003390L), 1, noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti2Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkNoData(program, 0x101003368L);
		checkRtti2Data(program, 0x101003390L, 1);
		checkNoData(program, 0x1010033a8L);
		checkNoData(program, 0x101003200L);
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti1Cmd_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateRtti1BackgroundCmd rtti1Cmd = new CreateRtti1BackgroundCmd(
			addr(program, 0x1010033a8L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti1Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkNoData(program, 0x101003368L);
		checkNoData(program, 0x101003390L);
		checkRtti1Data(program, 0x1010033a8L);
		checkNoData(program, 0x101003200L);
		checkNoData(program, 0x1010032f0L);
	}

	@Test
	public void testValidRtti0Cmd_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		CreateTypeDescriptorBackgroundCmd rtti0Cmd = new CreateTypeDescriptorBackgroundCmd(
			addr(program, 0x101005200L), noFollowValidationOptions, noFollowApplyOptions);

		int txID = program.startTransaction("Creating RTTI");
		boolean commit = false;
		try {
			boolean applied = rtti0Cmd.applyTo(program);
			assertTrue(applied);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkNoData(program, 0x101003340L);
		checkNoData(program, 0x101003368L);
		checkNoData(program, 0x101003390L);
		checkNoData(program, 0x1010033a8L);
		checkTypeDescriptorData(program, 0x101005200L, 16, 16, ".?AVBase@@");
		checkNoData(program, 0x1010032f0L);
	}

}
