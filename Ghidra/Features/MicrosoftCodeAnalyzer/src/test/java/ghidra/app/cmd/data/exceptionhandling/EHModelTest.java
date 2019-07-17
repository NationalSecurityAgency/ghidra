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

import org.junit.Test;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.scalar.Scalar;

public class EHModelTest extends AbstractEHTest {

	@Test
	public void testValidV1FuncInfo32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupV1FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380");
		Address address = builder.addr(0x01001340);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, model.getMagicNumber());
		assertEquals(1, model.getUnwindCount());
		assertEquals(builder.addr(0x01001364), model.getUnwindMapAddress());
		assertEquals(1, model.getTryBlockCount());
		assertEquals(builder.addr(0x0100136c), model.getTryBlockMapAddress());
		assertEquals(1, model.getIPToStateCount());
		assertEquals(builder.addr(0x01001380), model.getIPToStateMapAddress());
		try {
			model.getESTypeListAddress();
			model.getEHFlags();
			fail(
				"Shouldn't be able to retrieve TypeListAddress or EH flags in a version1 FuncInfo.");
		}
		catch (UndefinedValueException e) {
			// We expect to get this.
		}
	}

	@Test
	public void testValidV1FuncInfo32withBbtBits() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupV1FuncInfo32(builder, 0x01001340, 0x59930520, 1, "0x01001364", 1, "0x0100136c", 1,
			"0x01001380");
		Address address = builder.addr(0x01001340);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(2, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, model.getMagicNumber());
		assertEquals(1, model.getUnwindCount());
		assertEquals(builder.addr(0x01001364), model.getUnwindMapAddress());
		assertEquals(1, model.getTryBlockCount());
		assertEquals(builder.addr(0x0100136c), model.getTryBlockMapAddress());
		assertEquals(1, model.getIPToStateCount());
		assertEquals(builder.addr(0x01001380), model.getIPToStateMapAddress());
		try {
			model.getESTypeListAddress();
			fail("Shouldn't be able to retrieve TypeListAddress in a version1 FuncInfo.");
		}
		catch (UndefinedValueException e) {
			// We expect to get this.
		}
		try {
			model.getEHFlags();
			fail("Shouldn't be able to retrieve EH flags in a version1 FuncInfo.");
		}
		catch (UndefinedValueException e) {
			// We expect to get this.
		}
	}

	@Test
	public void testInvalidMagicNumV1FuncInfo32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupV1FuncInfo32(builder, 0x01001340, 0x49930520, 1, "0x01001364", 1, "0x0100136c", 1,
			"0x01001380");
		Address address = builder.addr(0x01001340);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		try {
			model.validate();
		}
		catch (InvalidDataTypeException e) {
			assertEquals("FuncInfo @ 01001340 doesn't have a valid magic number.", e.getMessage());
		}
	}

	@Test
	public void testValidV2FuncInfo32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupV2FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388");
		Address address = builder.addr(0x01001340);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, model.getMagicNumber());
		assertEquals(1, model.getUnwindCount());
		assertEquals(builder.addr(0x01001364), model.getUnwindMapAddress());
		assertEquals(1, model.getTryBlockCount());
		assertEquals(builder.addr(0x0100136c), model.getTryBlockMapAddress());
		assertEquals(1, model.getIPToStateCount());
		assertEquals(builder.addr(0x01001380), model.getIPToStateMapAddress());
		assertEquals(builder.addr(0x01001388), model.getESTypeListAddress());
		try {
			model.getEHFlags();
			fail("Shouldn't be able to retrieve EH flags in a version1 FuncInfo.");
		}
		catch (UndefinedValueException e) {
			// We expect to get this.
		}
	}

	@Test
	public void testValidV3FuncInfo32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupV3FuncInfo32(builder, 0x01001340, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388", 0x1);
		Address address = builder.addr(0x01001340);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, model.getMagicNumber());
		assertEquals(1, model.getUnwindCount());
		assertEquals(builder.addr(0x01001364), model.getUnwindMapAddress());
		assertEquals(1, model.getTryBlockCount());
		assertEquals(builder.addr(0x0100136c), model.getTryBlockMapAddress());
		assertEquals(1, model.getIPToStateCount());
		assertEquals(builder.addr(0x01001380), model.getIPToStateMapAddress());
		assertEquals(builder.addr(0x01001388), model.getESTypeListAddress());
		assertEquals(1, model.getEHFlags());
	}

	@Test
	public void testInvalidV3FuncInfo32NotAligned() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupV3FuncInfo32(builder, 0x01001341, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 1,
			"0x01001364", 1, "0x0100136c", 1, "0x01001380", "0x01001388", 0x1);
		Address address = builder.addr(0x01001341);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		try {
			model.validate();
		}
		catch (InvalidDataTypeException e) {
			assertEquals("FuncInfo data type is not properly aligned at 01001341.", e.getMessage());
		}
	}

	@Test
	public void testValidV1FuncInfo64() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		setupV1FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200);
		Address address = builder.addr(0x101003340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, model.getMagicNumber());
		assertEquals(3, model.getUnwindCount());
		assertEquals(builder.addr(0x101003368L), model.getUnwindMapAddress());
		assertEquals(2, model.getTryBlockCount());
		assertEquals(builder.addr(0x101003380L), model.getTryBlockMapAddress());
		assertEquals(4, model.getIPToStateCount());
		assertEquals(builder.addr(0x1010033d0L), model.getIPToStateMapAddress());
		assertEquals(0x200, model.getUnwindHelpDisplacement());
		try {
			model.getESTypeListAddress();
			model.getEHFlags();
			fail(
				"Shouldn't be able to retrieve TypeListAddress or EH flags in a version1 FuncInfo.");
		}
		catch (UndefinedValueException e) {
			// We expect to get this.
		}
	}

	@Test
	public void testInvalidV1FuncInfo64UnwindInOtherBlock() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		setupV1FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200);
		Address address = builder.addr(0x101003340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		try {
			model.validate();
		}
		catch (InvalidDataTypeException e) {
			assertEquals(
				"FuncInfo data type at 01003340 has a unwind map component that refers to an " +
					"address that is in a different memory block.",
				e.getMessage());
		}
	}

	@Test
	public void testInvalidV1FuncInfo64NonVS() throws Exception {
		ProgramBuilder builder = build64BitX86NonVS();
		ProgramDB program = builder.getProgram();
		setupV1FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V1, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200);
		Address address = builder.addr(0x101003340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		try {
			model.validate();
		}
		catch (InvalidDataTypeException e) {
			assertEquals("FuncInfo data type model is only valid for Visual Studio windows PE.",
				e.getMessage());
		}
	}

	@Test
	public void testValidV2FuncInfo64() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		setupV2FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0");
		Address address = builder.addr(0x101003340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V2, model.getMagicNumber());
		assertEquals(3, model.getUnwindCount());
		assertEquals(builder.addr(0x101003368L), model.getUnwindMapAddress());
		assertEquals(2, model.getTryBlockCount());
		assertEquals(builder.addr(0x101003380L), model.getTryBlockMapAddress());
		assertEquals(4, model.getIPToStateCount());
		assertEquals(builder.addr(0x1010033d0L), model.getIPToStateMapAddress());
		assertEquals(0x200, model.getUnwindHelpDisplacement());
		assertEquals(builder.addr(0x1010033f0L), model.getESTypeListAddress());
		try {
			model.getEHFlags();
			fail("Shouldn't be able to retrieve EH flags in a version1 FuncInfo.");
		}
		catch (UndefinedValueException e) {
			// We expect to get this.
		}
	}

	@Test
	public void testValidV3FuncInfo64() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());
		setupV3FuncInfo64(builder, 0x101001340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 1,
			"0x101001364", 1, "0x10100136c", 1, "0x101001380", 0x00000200, "0x101001388", 0x1);
		Address address = builder.addr(0x101001340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, model.getMagicNumber());
		assertEquals(1, model.getUnwindCount());
		assertEquals(builder.addr(0x101001364L), model.getUnwindMapAddress());
		assertEquals(1, model.getTryBlockCount());
		assertEquals(builder.addr(0x10100136cL), model.getTryBlockMapAddress());
		assertEquals(1, model.getIPToStateCount());
		assertEquals(builder.addr(0x101001380L), model.getIPToStateMapAddress());
		assertEquals(0x200, model.getUnwindHelpDisplacement());
		assertEquals(builder.addr(0x101001388L), model.getESTypeListAddress());
		assertEquals(1, model.getEHFlags());
	}

	@Test
	public void testInvalidV3FuncInfo64DoesNotFit() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());
		setupV3FuncInfo64(builder, 0x101002ff0L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 1,
			"0x101001364", 1, "0x10100136c", 1, "0x101001380", 0x00000200, "0x101001388", 0x1);
		Address address = builder.addr(0x101002ff0L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		try {
			model.validate();
		}
		catch (InvalidDataTypeException e) {
			assertEquals(
				"FuncInfo data type doesn't fit in a single memory block when placed at 101002ff0.",
				e.getMessage());
		}
	}

	@Test
	public void testValidUnwind32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupUnwind32(builder, 0x01001320, 0xFFFFFFFF, "0x01001360");
		Address address = builder.addr(0x01001320);
		EHUnwindModel model = new EHUnwindModel(program, 1, address, defaultValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(0xFFFFFFFF, model.getToState(0));
		assertEquals(builder.addr(0x01001360), model.getActionAddress(0));
	}

	@Test
	public void testValidTryBlock32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupTryBlock32(builder, 0x01001340, 0, 2, 3, 1, "0x01001380");
		Address address = builder.addr(0x01001340);
		EHTryBlockModel model = new EHTryBlockModel(program, 1, address, defaultValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getTryLow(0));
		assertEquals(2, model.getTryHigh(0));
		assertEquals(3, model.getCatchHigh(0));
		assertEquals(1, model.getCatchHandlerCount(0));
		assertEquals(builder.addr(0x01001380), model.getCatchHandlerMapAddress(0));
	}

	@Test
	public void testValidIPToState32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupIPToState32(builder, 0x01001340, 0x01001364, -1);
		Address address = builder.addr(0x01001340);
		EHIPToStateModel model =
			new EHIPToStateModel(program, 1, address, defaultValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(0x01001364, ((Scalar) model.getIP(0)).getValue());
		assertEquals(0xFFFFFFFF, model.getState(0));
	}

	@Test
	public void testValidCatchHandler32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupCatchHandler32(builder, 0x01001340, 1, "0x01005360", 0, "0x01001400");
		Address address = builder.addr(0x01001340);
		EHCatchHandlerModel model =
			new EHCatchHandlerModel(program, 1, address, defaultValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(new EHCatchHandlerTypeModifier(1), model.getModifiers(0));
		assertEquals(builder.addr(0x01005360), model.getTypeDescriptorAddress(0));
		assertEquals(0, model.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x01001400), model.getCatchHandlerAddress(0));
	}

	@Test
	public void testValidTypeDescriptor32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupTypeDescriptor32(builder, 0x01005340, "0x01001364", "0x00000000", "SomeError");
		Address address = builder.addr(0x01005340);
		TypeDescriptorModel model =
			new TypeDescriptorModel(program, address, defaultValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(builder.addr(0x01001364), model.getVFTableAddress());
		assertEquals(null, model.getSpareDataAddress());
		assertEquals("SomeError", model.getTypeName());
	}

	@Test
	public void testValidTypeList32() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		setupTypeList32(builder, 0x01001340, 1, "0x01001364");
		Address address = builder.addr(0x01001340);
		EHESTypeListModel model = new EHESTypeListModel(program, address, defaultValidationOptions);
		model.validate();
		assertEquals(address, model.getAddress());
		assertEquals(1, model.getHandlerTypeCount());
		assertEquals(builder.addr(0x01001364), model.getHandlerTypeMapAddress());
	}

	@Test
	public void testValidV3FuncInfo32CompleteFlow() throws Exception {
		ProgramBuilder builder = build32BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x01000000L), program.getImageBase());
		setupV3FuncInfo32CompleteFlow(builder);

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		Address address = builder.addr(0x01003340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, model.getMagicNumber());
		assertEquals(3, model.getUnwindCount());
		assertEquals(builder.addr(0x01003368L), model.getUnwindMapAddress());
		assertEquals(2, model.getTryBlockCount());
		assertEquals(builder.addr(0x01003380L), model.getTryBlockMapAddress());
		assertEquals(4, model.getIPToStateCount());
		assertEquals(builder.addr(0x010033d0L), model.getIPToStateMapAddress());
		try {
			model.getUnwindHelpDisplacement();
			fail("FuncInfo shouldn't have an unwind help displacement.");
		}
		catch (UndefinedValueException e) {
			// expect there to be no unwind help displacement.
		}
		assertEquals(builder.addr(0x010033f0L), model.getESTypeListAddress());
		assertEquals(1, model.getEHFlags());

		EHUnwindModel unwindModel = model.getUnwindModel();
		assertNotNull(unwindModel);
		unwindModel.validate();
		assertEquals(builder.addr(0x01003368L), unwindModel.getAddress());
		assertEquals(0xFFFFFFFF, unwindModel.getToState(0));
		assertEquals(builder.addr(0x01001200L), unwindModel.getActionAddress(0));
		assertEquals(0, unwindModel.getToState(1));
		assertEquals(builder.addr(0x01001214L), unwindModel.getActionAddress(1));
		assertEquals(1, unwindModel.getToState(2));
		assertEquals(builder.addr(0x01001230L), unwindModel.getActionAddress(2));

		EHTryBlockModel tryBlockModel = model.getTryBlockModel();
		assertNotNull(tryBlockModel);
		tryBlockModel.validate();
		assertEquals(builder.addr(0x01003380L), tryBlockModel.getAddress());
		assertEquals(2, tryBlockModel.getCount());
		// 1st Try
		assertEquals(2, tryBlockModel.getTryLow(0));
		assertEquals(2, tryBlockModel.getTryHigh(0));
		assertEquals(3, tryBlockModel.getCatchHigh(0));
		assertEquals(2, tryBlockModel.getCatchHandlerCount(0));
		assertEquals(builder.addr(0x010033a8L), tryBlockModel.getCatchHandlerMapAddress(0));
		// 2nd Try
		assertEquals(0, tryBlockModel.getTryLow(1));
		assertEquals(0, tryBlockModel.getTryHigh(1));
		assertEquals(1, tryBlockModel.getCatchHigh(1));
		assertEquals(1, tryBlockModel.getCatchHandlerCount(1));
		assertEquals(builder.addr(0x010032a0L), tryBlockModel.getCatchHandlerMapAddress(1));

		EHIPToStateModel ipToStateModel = model.getIPToStateModel();
		assertNotNull(ipToStateModel);
		ipToStateModel.validate();
		assertEquals(builder.addr(0x010033d0), ipToStateModel.getAddress());
		// 1st
		assertEquals(0x01001200, ((Scalar) ipToStateModel.getIP(0)).getValue());
		assertEquals(0xFFFFFFFF, ipToStateModel.getState(0));
		// 2nd
		assertEquals(0x01001300, ((Scalar) ipToStateModel.getIP(1)).getValue());
		assertEquals(0, ipToStateModel.getState(1));
		// 3rd
		assertEquals(0x01001400, ((Scalar) ipToStateModel.getIP(2)).getValue());
		assertEquals(1, ipToStateModel.getState(2));
		// 4th
		assertEquals(0x01001500, ((Scalar) ipToStateModel.getIP(3)).getValue());
		assertEquals(0, ipToStateModel.getState(3));

		// ESTypeList
		EHESTypeListModel esTypeListModel = model.getESTypeListModel();
		assertNotNull(esTypeListModel);
		esTypeListModel.validate();
		assertEquals(builder.addr(0x010033f0), esTypeListModel.getAddress());
		assertEquals(2, esTypeListModel.getHandlerTypeCount());
		assertEquals(builder.addr("0x01001800"), esTypeListModel.getHandlerTypeMapAddress());
		EHCatchHandlerModel catchHandlerModel = esTypeListModel.getCatchHandlerModel();
		assertNotNull(catchHandlerModel);
		catchHandlerModel.validate();
		assertEquals(builder.addr("0x01001800"), catchHandlerModel.getAddress());
		// 1st ESTypeList Catch Handler.
		assertEquals(new EHCatchHandlerTypeModifier(0), catchHandlerModel.getModifiers(0));
		assertEquals(builder.addr(0x01005400), catchHandlerModel.getTypeDescriptorAddress(0));
		assertEquals(0x32, catchHandlerModel.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x01001120), catchHandlerModel.getCatchHandlerAddress(0));
		// 2nd ESTypeList Catch Handler.
		assertEquals(new EHCatchHandlerTypeModifier(4), catchHandlerModel.getModifiers(1));
		assertEquals(null, catchHandlerModel.getTypeDescriptorAddress(1));
		assertEquals(0, catchHandlerModel.getCatchObjectDisplacement(1).getValue());
		assertEquals(builder.addr(0x01001140), catchHandlerModel.getCatchHandlerAddress(1));

		TypeDescriptorModel typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(0);
		assertNotNull(typeDescriptorModel);
		typeDescriptorModel.validate();
		assertEquals(builder.addr(0x01005400), typeDescriptorModel.getAddress());
		assertEquals(builder.addr(0x01003500), typeDescriptorModel.getVFTableAddress());
		assertEquals(null, typeDescriptorModel.getSpareDataAddress());
		assertEquals("NotReachableError", typeDescriptorModel.getTypeName());

		// 1st TryBlock's
		catchHandlerModel = tryBlockModel.getCatchHandlerModel(0);
		assertNotNull(catchHandlerModel);
		catchHandlerModel.validate();
		assertEquals(builder.addr(0x010033a8), catchHandlerModel.getAddress());

		// 1st TryBlock's 1st Catch
		assertEquals(new EHCatchHandlerTypeModifier(3), catchHandlerModel.getModifiers(0));
		assertEquals(builder.addr(0x01005400), catchHandlerModel.getTypeDescriptorAddress(0));
		assertEquals(5, catchHandlerModel.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x01001260), catchHandlerModel.getCatchHandlerAddress(0));

		typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(0);
		assertNotNull(typeDescriptorModel);
		typeDescriptorModel.validate();
		assertEquals(builder.addr(0x01005400), typeDescriptorModel.getAddress());
		assertEquals(builder.addr(0x01003500), typeDescriptorModel.getVFTableAddress());
		assertEquals(null, typeDescriptorModel.getSpareDataAddress());
		assertEquals("NotReachableError", typeDescriptorModel.getTypeName());

		// 1st TryBlock's 2nd Catch
		assertEquals(new EHCatchHandlerTypeModifier(0x40), catchHandlerModel.getModifiers(1));
		assertEquals(null, catchHandlerModel.getTypeDescriptorAddress(1));
		assertEquals(0, catchHandlerModel.getCatchObjectDisplacement(1).getValue());
		assertEquals(builder.addr(0x01001280), catchHandlerModel.getCatchHandlerAddress(1));

		typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(1);
		assertNull(typeDescriptorModel);

		// 2nd TryBlock's Only Catch
		catchHandlerModel = tryBlockModel.getCatchHandlerModel(1);
		assertNotNull(catchHandlerModel);
		catchHandlerModel.validate();
		assertEquals(builder.addr(0x010032a0), catchHandlerModel.getAddress());
		assertEquals(new EHCatchHandlerTypeModifier(5), catchHandlerModel.getModifiers(0));
		assertEquals(builder.addr(0x01005428), catchHandlerModel.getTypeDescriptorAddress(0));
		assertEquals(4, catchHandlerModel.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x010012a0), catchHandlerModel.getCatchHandlerAddress(0));

		typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(0);
		assertNotNull(typeDescriptorModel);
		typeDescriptorModel.validate();
		assertEquals(builder.addr(0x01005428), typeDescriptorModel.getAddress());
		assertEquals(builder.addr(0x01003540), typeDescriptorModel.getVFTableAddress());
		assertEquals(null, typeDescriptorModel.getSpareDataAddress());
		assertEquals("DataUnavailableError", typeDescriptorModel.getTypeName());
	}

	@Test
	public void testValidV3FuncInfo64CompleteFlow() throws Exception {
		ProgramBuilder builder = build64BitX86();
		ProgramDB program = builder.getProgram();
		assertEquals(builder.addr(0x101000000L), program.getImageBase());
		// FuncInfo
		setupV3FuncInfo64(builder, 0x101003340L, EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, 3,
			"0x101003368", 2, "0x101003380", 4, "0x1010033d0", 0x00000200, "0x1010033f0", 0x1); // 40 bytes
		// UnwindMap
		setupUnwind64(builder, 0x101003368L, 0xffffffff, "0x101001200"); // 8 bytes
		setupUnwind64(builder, 0x101003370L, 0x0, "0x101001214"); // 8 bytes
		setupUnwind64(builder, 0x101003378L, 0x1, "0x101001230"); // 8 bytes
		// TryBlockMap
		setupTryBlock64(builder, 0x101003380L, 2, 2, 3, 2, "0x1010033a8"); // 20 bytes
		setupTryBlock64(builder, 0x101003394L, 0, 0, 1, 1, "0x1010032a0"); // 20 bytes
		// CatchHandlerMap
		setupCatchHandler64(builder, 0x1010033a8L, 0x3, "0x101005400", 5, "0x101001260", 0x58); // 20 bytes
		setupCatchHandler64(builder, 0x1010033bcL, 0x40, "0x101000000", 0, "0x101001280", 0x58); // 20 bytes
		setupCatchHandler64(builder, 0x1010032a0L, 0x5, "0x101005428", 4, "0x1010012a0", 0x58); // 20 bytes
		// IPToStateMap
		setupIPToState64(builder, 0x1010033d0L, "0x101001200", 0xffffffff); // 8 bytes
		setupIPToState64(builder, 0x1010033d8L, "0x101001300", 0); // 8 bytes
		setupIPToState64(builder, 0x1010033e0L, "0x101001400", 1); // 8 bytes
		setupIPToState64(builder, 0x1010033e8L, "0x101001500", 0); // 8 bytes
		// ESTypeList
		setupTypeList64(builder, 0x1010033f0L, 2, "0x101001800");
		setupCatchHandler64(builder, 0x101001800L, 0x0, "0x101005400", 0x32, "0x101001120", 0x58); // 20 bytes
		setupCatchHandler64(builder, 0x101001814L, 0x4, "0x101000000", 0, "0x101001140", 0x58); // 20 bytes
		setupCode64Bytes(builder, "0x101001120");
		setupCode64Instructions(builder, "0x101001140");

		// UnwindCode1
		// UnwindCode2
		// UnwindCode3
		setupCode64Bytes(builder, "0x101001200");
		setupCode64Instructions(builder, "0x101001214");
		setupCode64Bytes(builder, "0x101001230");

		// CatchCode1ForTry1
		// CatchCode2ForTry1
		// CatchCode1ForTry2
		setupCode64Bytes(builder, "0x101001260");
		setupCode64Instructions(builder, "0x101001280");
		setupCode64Bytes(builder, "0x1010012a0");

		// TypeDescriptor 1
		// TypeDescriptor 2
		setupTypeDescriptor64(builder, 0x101005400L, "0x0000000101003500", "0x0000000000000000",
			"NotReachableError"); // 34 bytes + 6 align = 40
		setupTypeDescriptor64(builder, 0x101005428L, "0x0000000101003540", "0x0000000000000000",
			"DataUnavailableError"); // 37 bytes + 3 align = 40

		//////////////
		// Now check that everything gets laid down correctly on the structures.
		//////////////
		Address address = builder.addr(0x101003340L);
		EHFunctionInfoModel model =
			new EHFunctionInfoModel(program, address, defaultValidationOptions);
		model.validate();
		model.validateCounts(1000);
		model.validateLocationsInSameBlock();
		assertEquals(address, model.getAddress());
		assertEquals(0, model.getBbtFlags());
		assertEquals(EHFunctionInfoModel.EH_MAGIC_NUMBER_V3, model.getMagicNumber());
		assertEquals(3, model.getUnwindCount());
		assertEquals(builder.addr(0x101003368L), model.getUnwindMapAddress());
		assertEquals(2, model.getTryBlockCount());
		assertEquals(builder.addr(0x101003380L), model.getTryBlockMapAddress());
		assertEquals(4, model.getIPToStateCount());
		assertEquals(builder.addr(0x1010033d0L), model.getIPToStateMapAddress());
		assertEquals(0x200, model.getUnwindHelpDisplacement());
		assertEquals(builder.addr(0x1010033f0L), model.getESTypeListAddress());
		assertEquals(1, model.getEHFlags());

		EHUnwindModel unwindModel = model.getUnwindModel();
		assertNotNull(unwindModel);
		unwindModel.validate();
		assertEquals(builder.addr(0x101003368L), unwindModel.getAddress());
		assertEquals(0xFFFFFFFF, unwindModel.getToState(0));
		assertEquals(builder.addr(0x101001200L), unwindModel.getActionAddress(0));
		assertEquals(0, unwindModel.getToState(1));
		assertEquals(builder.addr(0x101001214L), unwindModel.getActionAddress(1));
		assertEquals(1, unwindModel.getToState(2));
		assertEquals(builder.addr(0x101001230L), unwindModel.getActionAddress(2));

		EHTryBlockModel tryBlockModel = model.getTryBlockModel();
		assertNotNull(tryBlockModel);
		tryBlockModel.validate();
		assertEquals(builder.addr(0x101003380L), tryBlockModel.getAddress());
		assertEquals(2, tryBlockModel.getCount());
		// 1st Try
		assertEquals(2, tryBlockModel.getTryLow(0));
		assertEquals(2, tryBlockModel.getTryHigh(0));
		assertEquals(3, tryBlockModel.getCatchHigh(0));
		assertEquals(2, tryBlockModel.getCatchHandlerCount(0));
		assertEquals(builder.addr(0x1010033a8L), tryBlockModel.getCatchHandlerMapAddress(0));
		// 2nd Try
		assertEquals(0, tryBlockModel.getTryLow(1));
		assertEquals(0, tryBlockModel.getTryHigh(1));
		assertEquals(1, tryBlockModel.getCatchHigh(1));
		assertEquals(1, tryBlockModel.getCatchHandlerCount(1));
		assertEquals(builder.addr(0x1010032a0L), tryBlockModel.getCatchHandlerMapAddress(1));

		EHIPToStateModel ipToStateModel = model.getIPToStateModel();
		assertNotNull(ipToStateModel);
		ipToStateModel.validate();
		assertEquals(builder.addr(0x1010033d0L), ipToStateModel.getAddress());
		// 1st
		assertEquals(builder.addr(0x101001200L), (ipToStateModel.getIP(0)));
		assertEquals(0xFFFFFFFF, ipToStateModel.getState(0));
		// 2nd
		assertEquals(builder.addr(0x101001300L), (ipToStateModel.getIP(1)));
		assertEquals(0, ipToStateModel.getState(1));
		// 3rd
		assertEquals(builder.addr(0x101001400L), (ipToStateModel.getIP(2)));
		assertEquals(1, ipToStateModel.getState(2));
		// 4th
		assertEquals(builder.addr(0x101001500L), (ipToStateModel.getIP(3)));
		assertEquals(0, ipToStateModel.getState(3));

		// ESTypeList
		EHESTypeListModel esTypeListModel = model.getESTypeListModel();
		assertNotNull(esTypeListModel);
		esTypeListModel.validate();
		assertEquals(builder.addr(0x1010033f0L), esTypeListModel.getAddress());
		assertEquals(2, esTypeListModel.getHandlerTypeCount());
		assertEquals(builder.addr("0x101001800"), esTypeListModel.getHandlerTypeMapAddress());
		EHCatchHandlerModel catchHandlerModel = esTypeListModel.getCatchHandlerModel();
		assertNotNull(catchHandlerModel);
		catchHandlerModel.validate();
		assertEquals(builder.addr("0x101001800"), catchHandlerModel.getAddress());
		// 1st ESTypeList Catch Handler.
		assertEquals(new EHCatchHandlerTypeModifier(0), catchHandlerModel.getModifiers(0));
		assertEquals(builder.addr(0x101005400L), catchHandlerModel.getTypeDescriptorAddress(0));
		assertEquals(0x32, catchHandlerModel.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x101001120L), catchHandlerModel.getCatchHandlerAddress(0));
		// 2nd ESTypeList Catch Handler.
		assertEquals(new EHCatchHandlerTypeModifier(4), catchHandlerModel.getModifiers(1));
		assertEquals(null, catchHandlerModel.getTypeDescriptorAddress(1));
		assertEquals(0, catchHandlerModel.getCatchObjectDisplacement(1).getValue());
		assertEquals(builder.addr(0x101001140L), catchHandlerModel.getCatchHandlerAddress(1));

		TypeDescriptorModel typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(0);
		assertNotNull(typeDescriptorModel);
		typeDescriptorModel.validate();
		assertEquals(builder.addr(0x101005400L), typeDescriptorModel.getAddress());
		assertEquals(builder.addr(0x101003500L), typeDescriptorModel.getVFTableAddress());
		assertEquals(null, typeDescriptorModel.getSpareDataAddress());
		assertEquals("NotReachableError", typeDescriptorModel.getTypeName());

		// 1st TryBlock's
		catchHandlerModel = tryBlockModel.getCatchHandlerModel(0);
		assertNotNull(catchHandlerModel);
		catchHandlerModel.validate();
		assertEquals(builder.addr(0x1010033a8L), catchHandlerModel.getAddress());

		// 1st TryBlock's 1st Catch
		assertEquals(new EHCatchHandlerTypeModifier(3), catchHandlerModel.getModifiers(0));
		assertEquals(builder.addr(0x101005400L), catchHandlerModel.getTypeDescriptorAddress(0));
		assertEquals(5, catchHandlerModel.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x101001260L), catchHandlerModel.getCatchHandlerAddress(0));

		typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(0);
		assertNotNull(typeDescriptorModel);
		typeDescriptorModel.validate();
		assertEquals(builder.addr(0x101005400L), typeDescriptorModel.getAddress());
		assertEquals(builder.addr(0x101003500L), typeDescriptorModel.getVFTableAddress());
		assertEquals(null, typeDescriptorModel.getSpareDataAddress());
		assertEquals("NotReachableError", typeDescriptorModel.getTypeName());

		// 1st TryBlock's 2nd Catch
		assertEquals(new EHCatchHandlerTypeModifier(0x40), catchHandlerModel.getModifiers(1));
		assertEquals(null, catchHandlerModel.getTypeDescriptorAddress(1));
		assertEquals(0, catchHandlerModel.getCatchObjectDisplacement(1).getValue());
		assertEquals(builder.addr(0x101001280L), catchHandlerModel.getCatchHandlerAddress(1));

		typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(1);
		assertNull(typeDescriptorModel);

		// 2nd TryBlock's Only Catch
		catchHandlerModel = tryBlockModel.getCatchHandlerModel(1);
		assertNotNull(catchHandlerModel);
		catchHandlerModel.validate();
		assertEquals(builder.addr(0x1010032a0L), catchHandlerModel.getAddress());
		assertEquals(new EHCatchHandlerTypeModifier(5), catchHandlerModel.getModifiers(0));
		assertEquals(builder.addr(0x101005428L), catchHandlerModel.getTypeDescriptorAddress(0));
		assertEquals(4, catchHandlerModel.getCatchObjectDisplacement(0).getValue());
		assertEquals(builder.addr(0x1010012a0L), catchHandlerModel.getCatchHandlerAddress(0));

		typeDescriptorModel = catchHandlerModel.getTypeDescriptorModel(0);
		assertNotNull(typeDescriptorModel);
		typeDescriptorModel.validate();
		assertEquals(builder.addr(0x101005428L), typeDescriptorModel.getAddress());
		assertEquals(builder.addr(0x101003540L), typeDescriptorModel.getVFTableAddress());
		assertEquals(null, typeDescriptorModel.getSpareDataAddress());
		assertEquals("DataUnavailableError", typeDescriptorModel.getTypeName());
	}
}
