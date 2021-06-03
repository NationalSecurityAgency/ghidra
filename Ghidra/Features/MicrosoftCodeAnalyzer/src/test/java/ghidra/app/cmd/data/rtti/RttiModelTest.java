/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;

public class RttiModelTest extends AbstractRttiTest {

	@Test
	public void testValidRtti4_32NoFollowData() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupRtti4_32(builder, 0x01001340L, 0, 0, 0, "0x01005364", "0x0100137c");
		Address address = builder.addr(0x01001340L);
		Rtti4Model model = new Rtti4Model(program, address, noFollowValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getSignature());
		assertEquals(0, model.getVbTableOffset());
		assertEquals(0, model.getConstructorOffset());
		assertEquals(builder.addr(0x01005364L), model.getRtti0Address());
		assertEquals(builder.addr(0x0100137cL), model.getRtti3Address());
	}

	@Test
	public void testInvalidRtti4_32wFollowDataToBadRtti0VfTableRef() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupRtti4_32(builder, 0x01001340L, 0, 0, 0, "0x01005364", "0x0100137c");
		Address address = builder.addr(0x01001340L);
		checkInvalidModel(new Rtti4Model(program, address, defaultValidationOptions),
			"TypeDescriptor data type at 01005364 doesn't point to a vfTable address in a loaded and initialized memory block.");
	}

	@Test
	public void testInvalidRtti4_32wFollowDataToBadRtti0_UninitBlock() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupRtti4_32(builder, 0x01001340L, 0, 0, 0, "0x01001364", "0x0100137c");
		setupRtti0_32(builder, 0x01001364, "0x01007700", "0x0", "stuff");
		Address address = builder.addr(0x01001340L);
		checkInvalidModel(new Rtti4Model(program, address, defaultValidationOptions),
			"TypeDescriptor data type at 01001364 doesn't point to a vfTable address in a loaded and initialized memory block.");
	}

	@Test
	public void testInvalidRtti4_32wRtti0OutsideMem() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupRtti4_32(builder, 0x01001340, 0, 0, 0, "0x01007364", "0x0100137c");
		Address address = builder.addr(0x01001340L);
		checkInvalidModel(new Rtti4Model(program, address, defaultValidationOptions),
			"TypeDescriptor data type isn't at a valid address 01007364.");
	}

	@Test
	public void testInvalidRtti4_32wRtti3OutsideMem() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupRtti4_32(builder, 0x01001340, 0, 0, 0, "0x01005364", "0x0100737c");
		setupRtti0_32(builder, 0x01005364L, "0x01003280", "0x00000000", ".?AVBase@@"); // 4 + 4 + 11 bytes + 1 align = 20
		Address address = builder.addr(0x01001340L);
		checkInvalidModel(new Rtti4Model(program, address, defaultValidationOptions),
			"RTTIClassHierarchyDescriptor data type isn't at a valid address 0100737c.");
	}

	@Test
	public void testInvalidRtti4_32OutsideMem() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		Address address = addr(program, 0x01007340L);
		checkInvalidModel(new Rtti4Model(program, address, defaultValidationOptions),
			"RTTICompleteObjectLocator data type isn't at a valid address 01007340.");
	}

	@Test
	public void testValidRtti_32PartialFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti4:  01003340 - 01003353
		// rtti3:  01003368 - 01003377
		// rtti2:  01003390 - 01003393
		// rtti1:  010033a8 - 010033c3
		// rtti0:  01003200 - 01003213
		// vfTbl:  010032f0 - 010032fb
		//
		setupRtti4_32(builder, 0x01003340L, 0, 0, 0, "0x01005200", "0x01003368"); // 20 bytes
		setupRtti3_32(builder, 0x01003368L, 0, 0, 1, "0x01003380"); // 16 bytes
		setupRtti2_32(builder, 0x01003380L, new String[] { "0x010033a8" }); // 4 bytes
		setupRtti0_32(builder, 0x01005200L, "0x01003280", "0x00000000", ".?AVBase@@"); // 4 + 4 + 11 bytes + 1 align = 20
		setupVfTable_32(builder, 0x010032f0L, "0x01003340",
			new String[] { "0x01001200", "0x01001280" }); // 12 bytes

		setupInstructions32(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		Address address = addr(program, 0x01003340L);
		Rtti4Model model = new Rtti4Model(program, address, defaultValidationOptions);
		try {
			model.validate();
			Assert.fail("Model validation should have failed when following data.");
		}
		catch (InvalidDataTypeException e) {
			// Should fail validation since no data at RTTI 0.
			assertEquals("RTTIBaseClassDescriptor data type at 010033a8 isn't valid. " +
				"TypeDescriptor data type isn't at a valid address 00000000.", e.getMessage());
		}
	}

	@Test
	public void testValidRtti_32CompleteFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti4:  01003340 - 01003353
		// rtti3:  01003368 - 01003377
		// rtti2:  01003390 - 01003393
		// rtti1:  010033a8 - 010033c3
		// rtti0:  01005200 - 01003213
		// vfTbl:  010032f0 - 010032fb
		//
		setupRtti4_32(builder, 0x01003340L, 0, 0, 0, "0x01005200", "0x01003368"); // 20 bytes
		setupRtti3_32(builder, 0x01003368L, 0, 0, 1, "0x01003380"); // 16 bytes
		setupRtti2_32(builder, 0x01003380L, new String[] { "0x010033a8" }); // 4 bytes
		setupRtti1_32(builder, 0x010033a8L, "0x01005200", 0, 0, 0xffffffff, 0, 0x40, "0x01003368"); // 28 bytes
		setupRtti0_32(builder, 0x01005200L, "0x01003280", "0x00000000", ".?AVBase@@"); // 4 + 4 + 11 bytes + 1 align = 20
		setupVfTable_32(builder, 0x010032f0L, "0x01003340",
			new String[] { "0x01001200", "0x01001280" }); // 12 bytes

		setupInstructions32(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		checkRtti4Model(program, 0x01003340L, 0, 0, 0, 0x01005200L, 0x01003368L);
		checkRtti3Model(program, 0x01003368L, 0, 0, 1, 0x01003380L);
		checkRtti2Model(program, 0x01003380L, new long[] { 0x010033a8L });
		checkRtti1Model(program, 0x010033a8L, 0x01005200L, 0, 0, 0xffffffff, 0, 0x40, 0x01003368L);
		checkRtti0Model(program, 0x01005200L, 0x01003280L, 0x0L, ".?AVBase@@");
		checkVfTableModel(program, 0x010032f0L, 0x01003340L, 0x010032f4L,
			new long[] { 0x01001200L, 0x01001280L });
	}

	@Test
	public void testValidRtti4_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti4:  01003340 - 01003353
		//
		setupRtti4_32(builder, 0x01003340L, 0, 0, 0, "0x01005200", "0x01003368"); // 20 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		checkRtti4ModelNoFollow(program, 0x01003340L, 0, 0, 0, 0x01005200L, 0x01003368L);
	}

	@Test
	public void testValidRtti3_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti3:  01003368 - 01003377
		//
		setupRtti3_32(builder, 0x01003368L, 0, 0, 1, "0x01003380"); // 16 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		checkRtti3ModelNoFollow(program, 0x01003368L, 0, 0, 1, 0x01003380L);
	}

	@Test
	public void testValidRtti2_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti2:  01003390 - 01003393
		//
		setupRtti2_32(builder, 0x01003380L, new String[] { "0x010033a8" }); // 4 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		checkRtti2ModelNoFollow(program, 0x01003380L, new long[] { 0x010033a8L });
	}

	@Test
	public void testValidRtti1_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti1:  010033a8 - 010033c3
		//
		setupRtti1_32(builder, 0x010033a8L, "0x01005200", 0, 0, 0xffffffff, 0, 0x40, "0x01003368"); // 28 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		checkRtti1ModelNoFollow(program, 0x010033a8L, 0x01005200L, 0, 0, 0xffffffff, 0, 0x40,
			0x01003368L);
	}

	@Test
	public void testValidRtti0_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti0:  01003200 - 01003213
		//
		setupRtti0_32(builder, 0x01005200L, "0x01003280", "0x00000000", ".?AVBase@@"); // 4 + 4 + 11 bytes + 1 align = 20

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		checkRtti0ModelNoFollow(program, 0x01005200L, 0x01003280L, 0x0L, ".?AVBase@@");
	}

	@Test
	public void testValidVfTable_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// vfTbl:  010032f0 - 010032fb
		//
		setupVfTable_32(builder, 0x010032f0L, "0x01003340",
			new String[] { "0x01001200", "0x01001280" }); // 12 bytes

		// instructions
		setupCode32Bytes(builder, "0x01001200");
		setupCode32Bytes(builder, "0x01001280");

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		checkVfTableNoFollowModel(program, 0x010032f0L, 0x01003340L, 0x010032f4L,
			new long[] { 0x01001200L, 0x01001280L });
	}

	@Test
	public void testInvalidRtti4_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti4:  01003340 - 01003353
		//
		setupRtti4_32(builder, 0x01003340L, 0, 0, 0, "0x01005200", "0x0100"); // 20 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		String errorMessage =
			"Data referencing RTTIClassHierarchyDescriptor data type isn't a loaded and initialized address 00000100.";
		Address address = addr(program, 0x01003340L);
		checkInvalidModel(new Rtti4Model(program, address, noFollowValidationOptions),
			errorMessage);
	}

	@Test
	public void testInvalidRtti3_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti3:  01003368 - 01003377
		//
		setupRtti3_32(builder, 0x01003368L, 0, 0, 0, "0x01003380"); // 16 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		String errorMessage =
			"RTTIClassHierarchyDescriptor data type at 01003368 doesn't have a valid " +
				"RTTIBaseClassDescriptor count.";
		Address address = addr(program, 0x01003368L);
		checkInvalidModel(new Rtti3Model(program, address, noFollowValidationOptions),
			errorMessage);
	}

	@Test
	public void testInvalidRtti2_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti2:  01003390 - 01003393
		//
		setupRtti2_32(builder, 0x01003380L, new String[] { "0x010073a8" }); // 4 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		String errorMessage = "RTTIBaseClassArray data type at 01003380 isn't valid.";
		Address address = addr(program, 0x01003380L);
		checkInvalidModel(new Rtti2Model(program, 1, address, noFollowValidationOptions),
			errorMessage);
	}

	@Test
	public void testInvalidRtti1_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti1:  010033a8 - 010033c3
		//
		setupRtti1_32(builder, 0x010033a8L, "0x01005200", 0, 0xffffffff, 0xffffffff, 0, 0x40,
			"0x01003368"); // 28 bytes

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		String errorMessage = "RTTIBaseClassDescriptor data type at 010033a8 isn't valid.";
		Address address = addr(program, 0x010033a8L);
		checkInvalidModel(new Rtti1Model(program, address, noFollowValidationOptions),
			errorMessage);
	}

	@Test
	public void testInvalidRtti0_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// rtti0:  01005200 - 01003213
		//
		setupRtti0_32(builder, 0x01005200L, "0x0100", "0x00000000", ".?AVBase@@"); // 4 + 4 + 11 bytes + 1 align = 20

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		String errorMessage =
			"TypeDescriptor data type at 01005200 doesn't point to a vfTable address in a loaded and initialized memory block.";
		Address address = addr(program, 0x01005200L);
		checkInvalidModel(new TypeDescriptorModel(program, address, noFollowValidationOptions),
			errorMessage);
	}

	@Test
	public void testInvalidVfTable_32NoFollowFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		// ---- Base ----
		// vfTbl:  010032f0 - 010032fb
		//
		setupVfTable_32(builder, 0x010032f0L, "0x01003340",
			new String[] { "0x01001200", "0x01001280" }); // 12 bytes

		//////////////
		// Now check that the structure model fails.
		//////////////
		String errorMessage = "Cannot determine length for vftable data type at 010032f0.";
		Address address = addr(program, 0x010032f0L);
		checkInvalidModel(new VfTableModel(program, address, noFollowValidationOptions),
			errorMessage);
	}

	@Test
	public void testValidInheritanceRtti_32CompleteFlow() throws Exception {

		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());

		setupRtti32CompleteFlow(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4Model(program, 0x01003340L, 0, 0, 0, 0x01005200L, 0x01003368L);
		checkRtti3Model(program, 0x01003368L, 0, 0, 1, 0x01003390L);
		checkRtti2Model(program, 0x01003390L, new long[] { 0x010033a8L });
		checkRtti1Model(program, 0x010033a8L, 0x01005200L, 0, 0, 0xffffffff, 0, 0x40, 0x01003368L);
		checkRtti0Model(program, 0x01005200L, 0x01003280L, 0x0L, ".?AVBase@@");
		checkVfTableModel(program, 0x010032f0L, 0x01003340L, 0x010032f4L,
			new long[] { 0x01001200L, 0x01001280L });

		// ---- check Shape ----
		checkRtti4Model(program, 0x01003354L, 0, 0, 0, 0x01005214L, 0x01003378L);
		checkRtti3Model(program, 0x01003378L, 0, 0, 2, 0x01003394L);
		checkRtti2Model(program, 0x01003394L, new long[] { 0x010033c4L, 0x010033a8L });
		checkRtti1Model(program, 0x010033c4L, 0x01005214L, 0, 0, 0xffffffff, 0, 0x40, 0x01003378L);
		checkRtti0Model(program, 0x01005214L, 0x01003280L, 0x0L, ".?AVShape@@");
		checkVfTableModel(program, 0x01003230L, 0x01003354L, 0x01003234L,
			new long[] { 0x01001214L, 0x01001230L });

		// ---- check Circle ----
		checkRtti4Model(program, 0x01003240L, 0, 0, 0, 0x010053e0L, 0x01003268L);
		checkRtti3Model(program, 0x01003268L, 0, 0, 3, 0x01003290L);
		checkRtti2Model(program, 0x01003290L, new long[] { 0x010032a8L, 0x010033c4L, 0x010033a8L });
		checkRtti1Model(program, 0x010032a8L, 0x010053e0L, 0, 0, 0xffffffff, 0, 0x40, 0x01003268L);
		checkRtti0Model(program, 0x010053e0L, 0x01003280L, 0x0L, ".?AVCircle@@");
		checkVfTableModel(program, 0x010031f0, 0x01003240L, 0x010031f4L,
			new long[] { 0x01001260L, 0x010012a0L });

	}

	@Test
	public void testValidInheritanceRtti_64CompleteFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64CompleteFlow(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4Model(program, 0x101003340L, 0, 0, 0, 0x101005200L, 0x101003368L);
		checkRtti3Model(program, 0x101003368L, 0, 0, 1, 0x101003390L);
		checkRtti2Model(program, 0x101003390L, new long[] { 0x1010033a8L });
		checkRtti1Model(program, 0x1010033a8L, 0x101005200L, 0, 0, 0xffffffff, 0, 0x40,
			0x101003368L);
		checkRtti0Model(program, 0x101005200L, 0x101003280L, 0x0L, ".?AVBase@@");
		checkVfTableModel(program, 0x1010032f0L, 0x101003340L, 0x1010032f8L,
			new long[] { 0x101001200L, 0x101001280L });

		// ---- check Shape ----
		checkRtti4Model(program, 0x101003354L, 0, 0, 0, 0x101005220L, 0x101003378L);
		checkRtti3Model(program, 0x101003378L, 0, 0, 2, 0x101003394L);
		checkRtti2Model(program, 0x101003394L, new long[] { 0x1010033c4L, 0x1010033a8L });
		checkRtti1Model(program, 0x1010033c4L, 0x101005220L, 0, 0, 0xffffffff, 0, 0x40,
			0x101003378L);
		checkRtti0Model(program, 0x101005220L, 0x101003280L, 0x0L, ".?AVShape@@");
		checkVfTableModel(program, 0x1010031b0L, 0x101003354L, 0x1010031b8L,
			new long[] { 0x101001214L, 0x101001230L });

		// ---- check Circle ----
		checkRtti4Model(program, 0x10100324cL, 0, 0, 0, 0x1010053e0L, 0x101003268L);
		checkRtti3Model(program, 0x101003268L, 0, 0, 3, 0x101003290L);
		checkRtti2Model(program, 0x101003290L,
			new long[] { 0x1010032a8L, 0x1010033c4L, 0x1010033a8L });
		checkRtti1Model(program, 0x1010032a8L, 0x1010053e0L, 0, 0, 0xffffffff, 0, 0x40,
			0x101003268L);
		checkRtti0Model(program, 0x1010053e0L, 0x101003280L, 0x0L, ".?AVCircle@@");
		checkVfTableModel(program, 0x1010031d0L, 0x10100324cL, 0x1010031d8L,
			new long[] { 0x101001260L, 0x1010012a0L, 0x101001120L });

	}

	@Test
	public void testValidRtti4Model_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		// ---- Base ----
		// rtti4:  101003340 - 101003353
		//
		setupRtti4_64(builder, 0x101003340L, 0, 0, 0, "0x101005200", "0x101003368"); // 20 bytes

		setupInstructions64(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti4ModelNoFollow(program, 0x101003340L, 0, 0, 0, 0x101005200L, 0x101003368L);
	}

	@Test
	public void testValidRtti3Model_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		// ---- Base ----
		// rtti3:  101003368 - 101003377
		//
		setupRtti3_64(builder, 0x101003368L, 0, 0, 1, "0x101003390"); // 16 bytes

		setupInstructions64(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti3ModelNoFollow(program, 0x101003368L, 0, 0, 1, 0x101003390L);
	}

	@Test
	public void testValidRtti2Model_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		// ---- Base ----
		// rtti2:  101003390 - 101003393
		//
		setupRtti2_64(builder, 0x101003390L, new String[] { "0x1010033a8" }); // 4 bytes

		setupInstructions64(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti2ModelNoFollow(program, 0x101003390L, new long[] { 0x1010033a8L });
	}

	@Test
	public void testValidRtti1Model_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		// ---- Base ----
		// rtti1:  1010033a8 - 1010033c3
		//
		setupRtti1_64(builder, 0x1010033a8L, "0x101005200", 0, 0, 0xffffffff, 0, 0x40,
			"0x101003368"); // 28 bytes (? 28 bytes?)

		setupInstructions64(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti1ModelNoFollow(program, 0x1010033a8L, 0x101005200L, 0, 0, 0xffffffff, 0, 0x40,
			0x101003368L);
	}

	@Test
	public void testValidRtti0Model_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		// ---- Base ----
		// rtti0:  101003200 - 10100321b
		//
		setupRtti0_64(builder, 0x101005200L, "0x101003280", "0x00000000", ".?AVBase@@"); // 8 + 8 + 11 bytes + 1 align = 28

		setupInstructions64(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkRtti0ModelNoFollow(program, 0x101005200L, 0x101003280L, 0x0L, ".?AVBase@@");
	}

	@Test
	public void testValidVfTableModel_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		// ---- Base ----
		// vfTbl:  1010032f0 - 101003307
		//
		setupVfTable_64(builder, 0x1010032f0L, "0x101003340",
			new String[] { "0x101001200", "0x101001280" }); // 8 + (2 * 8) bytes = 24

		setupInstructions64(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////

		// ---- check Base ----
		checkVfTableNoFollowModel(program, 0x1010032f0L, 0x101003340L, 0x1010032f8L,
			new long[] { 0x101001200L, 0x101001280L });
	}

	@Test
	public void testInstructionsInWayRtti1_64NoFollowFlow() throws Exception {

		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());

		setupRtti64Base(builder);

		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		String byteString = getHexAddressAsIbo32ByteString(builder, "0x101003200", bigEndian);
		builder.setBytes("0x1010033a8", byteString, true);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		String errorMessage =
			"Instructions are in the way of 1 RTTIBaseClassDescriptor data type(s) at 1010033a8.";
		Address address = addr(program, 0x1010033a8L);
		checkInvalidModel(new Rtti1Model(program, address, noFollowValidationOptions),
			errorMessage);
	}

}
