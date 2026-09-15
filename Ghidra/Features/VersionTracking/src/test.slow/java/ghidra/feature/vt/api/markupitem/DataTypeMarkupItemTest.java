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
package ghidra.feature.vt.api.markupitem;

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.*;
import static ghidra.feature.vt.db.VTTestUtils.*;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.DataTypeMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.DataTypeConflictChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.ReplaceDataChoices;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class DataTypeMarkupItemTest extends AbstractVTMarkupItemTest {

	@Test
	public void testReplaceDataTypeWhereNone() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		Data destinationData = destinationProgram.getListing().getDataAt(destinationAddress);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testMatchingDataTypes() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		TerminatedStringDataType destinationDataType = new TerminatedStringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, -1); // Get "LoadCursorW".

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndDoNothingOnApplyOfSameMarkupItem(validator);
	}

	@Test
	public void testReplaceSmallDataTypeWithLargerThatFits() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testReplace_ConflictInDtm_ChooseExistingType() throws Exception {

		Address srcAddr = addr("0x010074e6", sourceProgram);
		StructureDataType coolStruct1 = createCoolStruct1();
		Data sourceData = setDataType(sourceProgram, srcAddr, coolStruct1, coolStruct1.getLength());

		// Add a type to the destination that has the same data type path, but is not equivalent
		StructureDataType coolStruct2 = createCoolStruct2();
		addToDestinationDtm(coolStruct2);

		// make room for the type to be applied
		Address destAddr = addr("0x010074e6", destinationProgram);
		clear(destinationProgram, destAddr, coolStruct2.getLength());

		StringDataType destDt = new StringDataType();
		Data destData = setDataType(destinationProgram, destAddr, destDt, 4);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		validator.setConflictChoice(DataTypeConflictChoices.USE_EXISTING);
		validator.setKeepExistingType(true);
		doTestFindAndApplyMarkupItem(validator);

		assertConflictTypeInDestinationDtm(coolStruct1, false);
	}

	@Test
	public void testReplace_ConflictInDtm_ChooseRenameAndAdd() throws Exception {

		Address srcAddr = addr("0x010074e6", sourceProgram);
		StructureDataType coolStruct1 = createCoolStruct1();
		Data sourceData = setDataType(sourceProgram, srcAddr, coolStruct1, coolStruct1.getLength());

		// Add a type to the destination that has the same data type path, but is not equivalent
		StructureDataType coolStruct2 = createCoolStruct2();
		addToDestinationDtm(coolStruct2);

		Address destAddr = addr("0x010074e6", destinationProgram);
		StringDataType destDt = new StringDataType();
		Data destData = setDataType(destinationProgram, destAddr, destDt, 4);
		setDataType(destinationProgram, destAddr.add(4), destDt, 6);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		validator.setConflictChoice(DataTypeConflictChoices.RENAME_AND_ADD);
		doTestFindAndApplyMarkupItem(validator);

		assertConflictTypeInDestinationDtm(coolStruct1, true);
	}

	@Test
	public void testReplaceLargerWithSmaller() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram);
		StructureDataType sourceDataType = new StructureDataType("StructA", 0);
		sourceDataType.add(new DWordDataType());
		Data sourceData =
			setDataType(sourceProgram, sourceAddress, sourceDataType, sourceDataType.getLength());

		Address destinationAddress = addr("0x010074e6", destinationProgram);
		StructureDataType destinationDataType = new StructureDataType("StructB", 0);
		destinationDataType.add(new ArrayDataType(new CharDataType(), 12, 1));
		Data destinationData = setDataType(destinationProgram, destinationAddress,
			destinationDataType, destinationDataType.getLength());

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testReplaceWithLargerWhenBlockedByDataDoNothing() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW 
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW". 

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW 
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load". 
		setDataType(destinationProgram, destinationAddress.add(4), destinationDataType, 6); // Get "Cursor". 

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testReplaceAllWithLargerWhenHasData() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		setDataType(destinationProgram, destinationAddress.add(4), destinationDataType, 6); // Get "Cursor".

		DataTypeValidator validator =
			new DataTypeValidator(sourceData, destinationData, ReplaceDataChoices.REPLACE_ALL_DATA);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testReplaceAllWithLargerWhenHasDataAtEnd() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		setDataType(destinationProgram, destinationAddress.add(11), new ByteDataType(), -1); // Get "Cursor".

		DataTypeValidator validator =
			new DataTypeValidator(sourceData, destinationData, ReplaceDataChoices.REPLACE_ALL_DATA);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testReplaceFirstWithLargerWhenBlockedByDataAtEndDoNothing() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW 
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW". 

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW 
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load". 
		setDataType(destinationProgram, destinationAddress.add(11), new ByteDataType(), -1); // Get "Cursor". 

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testReplaceWithLargerWhenBlockedByInstruction() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		Address instructionAddress = destinationAddress.add(4);
		Instruction instruction = createInstruction(destinationProgram, instructionAddress);
		assertNotNull(instruction);
		Listing listing = destinationProgram.getListing();
		Instruction instructionAt = listing.getInstructionAt(instructionAddress);
		assertNotNull(instructionAt);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testReplaceUndefinedOnlyDataTypeWhereNone() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		Data destinationData = destinationProgram.getListing().getDataAt(destinationAddress);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testReplaceUndefinedOnlyMatchingDataTypes() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		TerminatedStringDataType destinationDataType = new TerminatedStringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, -1); // Get "LoadCursorW".

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndDoNothingOnApplyOfSameMarkupItem(validator);
	}

	@Test
	public void testReplaceUndefinedOnlySmallDataTypeWithLargerThatFits() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testReplaceUndefinedOnlyLargerWithSmaller() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram);
		StructureDataType sourceDataType = new StructureDataType("StructA", 0);
		sourceDataType.add(new DWordDataType());
		Data sourceData =
			setDataType(sourceProgram, sourceAddress, sourceDataType, sourceDataType.getLength());

		Address destinationAddress = addr("0x010074e6", destinationProgram);
		StructureDataType destinationDataType = new StructureDataType("StructB", 0);
		destinationDataType.add(new ArrayDataType(new CharDataType(), 12, 1));
		Data destinationData = setDataType(destinationProgram, destinationAddress,
			destinationDataType, destinationDataType.getLength());

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testReplaceUndefinedOnlyWithLargerWhenBlockedByData() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		setDataType(destinationProgram, destinationAddress.add(4), destinationDataType, 6); // Get "Cursor".

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testReplaceUndefinedOnlyWithLargerWhenBlockedByDataAtEnd() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		setDataType(destinationProgram, destinationAddress.add(11), new ByteDataType(), -1); // Get "Cursor".

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testRejectedApplyDoesNotMutateDestinationDataTypeManager() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		StructureDataType sourceDataType = new StructureDataType("RejectedApplyStruct", 0);
		sourceDataType.add(new DWordDataType());
		Data sourceData =
			setDataType(sourceProgram, sourceAddress, sourceDataType, sourceDataType.getLength());

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		setDataType(destinationProgram, destinationAddress.add(4), destinationDataType, 6); // Get "Cursor".

		DataTypeManager destinationDTM = destinationProgram.getDataTypeManager();
		assertNull("Test setup invalid - destination should not already have this data type",
			destinationDTM.getDataType(sourceDataType.getCategoryPath(),
				sourceDataType.getName()));

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY);
		validator.setConflictChoice(DataTypeConflictChoices.RENAME_AND_ADD);
		doTestFindAndApplyMarkupItem_NoEffect(validator);

		assertNull(
			"Rejected apply must not add the source data type to the destination data type " +
				"manager",
			destinationDTM.getDataType(sourceDataType.getCategoryPath(),
				sourceDataType.getName()));
	}

	@Test
	public void testReplaceUndefinedOnlyWithLargerWhenBlockedByInstruction() throws Exception {

		Address sourceAddress = addr("0x010074e6", sourceProgram); // LoadCursorW
		TerminatedStringDataType sourceDataType = new TerminatedStringDataType();
		Data sourceData = setDataType(sourceProgram, sourceAddress, sourceDataType, -1); // Get "LoadCursorW".

		Address destinationAddress = addr("0x010074e6", destinationProgram); // LoadCursorW
		StringDataType destinationDataType = new StringDataType();
		Data destinationData =
			setDataType(destinationProgram, destinationAddress, destinationDataType, 4); // Get "Load".
		Address instructionAddress = destinationAddress.add(4);
		Instruction instruction = createInstruction(destinationProgram, instructionAddress);
		assertNotNull(instruction);
		Listing listing = destinationProgram.getListing();
		Instruction instructionAt = listing.getInstructionAt(instructionAddress);
		assertNotNull(instructionAt);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testReplace_EmptyStructureOption_MatchingData() throws Exception {

		// apply a Gadget struct to the source
		Structure gadget = createGadgetStruct();
		String dataAddr = "0x01007500";
		sourceBuilder.setBytes(dataAddr, "4c 6f 61 64 43 75 72 73 6f 72 57 00"); // arbitrary bytes
		sourceBuilder.applyDataType(dataAddr, gadget);
		Address sourceAddr = addr(dataAddr, sourceProgram);
		Data sourceData = sourceProgram.getListing().getDataAt(sourceAddr);

		destinationBuilder.setBytes(dataAddr, "4c 6f 61 64 43 75 72 73 6f 72 57 00"); // same bytes
		destinationBuilder.applyDataType(dataAddr, gadget);
		Address destinationAddr = addr(dataAddr, destinationProgram);
		Data destinationData = destinationProgram.getListing().getDataAt(destinationAddr);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY) {
			@Override
			protected void assertApplied() {

				Data appliedData =
					destinationProgram.getListing().getDataAt(destinationAddr);
				DataType dt = appliedData.getDataType();
				assertTrue(dt instanceof Structure);
				Structure struct = (Structure) dt;
				assertEquals("Gadget", struct.getName());
				assertTrue("Struct should have been empty due to options setting",
					struct.isNotYetDefined());
			}

			@Override
			public ToolOptions getOptions() {
				ToolOptions vtOptions = super.getOptions();
				vtOptions.setBoolean(VTOptionDefines.USE_EMPTY_COMPOSITES, true);
				return vtOptions;
			}
		};
		doTestFindAndDoNothingOnApplyOfSameMarkupItem(validator);
	}

	@Test
	public void testReplace_EmptyStructureOption_WhereNone() throws Exception {

		// apply a Gadget struct to the source
		Structure gadget = createGadgetStruct();
		String dataAddr = "0x01007500";
		sourceBuilder.setBytes(dataAddr, "4c 6f 61 64 43 75 72 73 6f 72 57 00"); // arbitrary bytes
		sourceBuilder.applyDataType(dataAddr, gadget);
		Address sourceAddr = addr(dataAddr, sourceProgram);
		Data sourceData = sourceProgram.getListing().getDataAt(sourceAddr);

		destinationBuilder.setBytes(dataAddr, "4c 6f 61 64 43 75 72 73 6f 72 57 00"); // same bytes
		Address destinationAddr = addr(dataAddr, destinationProgram);
		Data destinationData = destinationProgram.getListing().getDataAt(destinationAddr);

		DataTypeValidator validator = new DataTypeValidator(sourceData, destinationData,
			ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY) {
			@Override
			protected void assertApplied() {

				Data appliedData =
					destinationProgram.getListing().getDataAt(destinationAddr);
				DataType dt = appliedData.getDataType();
				assertTrue(dt instanceof Structure);
				Structure struct = (Structure) dt;
				assertEquals("Gadget", struct.getName());
				assertTrue("Struct should have been empty due to options setting",
					struct.isNotYetDefined());
			}

			@Override
			public ToolOptions getOptions() {
				ToolOptions vtOptions = super.getOptions();
				vtOptions.setBoolean(VTOptionDefines.USE_EMPTY_COMPOSITES, true);
				return vtOptions;
			}
		};
		doTestFindAndApplyMarkupItem(validator);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void addToDestinationDtm(StructureDataType struct) {
		ProgramDataTypeManager destDtm = destinationProgram.getDataTypeManager();
		tx(destDtm, () -> {
			destDtm.resolve(struct, null);
		});

		DataTypePath dtp = struct.getDataTypePath();
		DataType resolvedDtm = destDtm.getDataType(dtp);
		assertNotNull(resolvedDtm);
	}

	private StructureDataType createCoolStruct1() {
		StructureDataType struct = new StructureDataType("CoolStructure", 0);
		struct.add(new DWordDataType());
		return struct;
	}

	// 'CoolStructure' that is slightly different than that made in createCoolStruct1()
	private StructureDataType createCoolStruct2() {
		StructureDataType struct = new StructureDataType("CoolStructure", 0);
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		return struct;
	}

	private void assertConflictTypeInDestinationDtm(DataType dt, boolean expectConflict) {

		DataTypePath dtp = dt.getDataTypePath();
		String name = dt.getName() + ".conflict";
		CategoryPath cp = dtp.getCategoryPath();
		DataTypePath conflictPath = new DataTypePath(cp, name);

		ProgramDataTypeManager destDtm = destinationProgram.getDataTypeManager();
		DataType conflictType = destDtm.getDataType(conflictPath);
		if (expectConflict) {
			assertNotNull(conflictType);
		}
		else {
			assertNull(conflictType);
		}
	}

	private Structure createGadgetStruct() {

		Structure gadgetStruct = new StructureDataType("Gadget", 0);
		PointerDataType charPtr = new PointerDataType(new CharDataType());
		gadgetStruct.add(charPtr, "name", "");
		gadgetStruct.add(new IntegerDataType(), "type", "");
		gadgetStruct.add(new BooleanDataType(), "deployed", "");
		gadgetStruct.add(new PointerDataType(), "workingOn", "");

		return gadgetStruct;

	}

	private Data setDataType(Program program, Address address, DataType dataType, int length) {

		return tx(program, () -> {
			Listing listing = program.getListing();
			Data sourceData = listing.getDataAt(address);
			if (sourceData == null) {
				return null;
			}

			listing.clearCodeUnits(address, sourceData.getMaxAddress(), false);
			Data data;
			if (length > 0) {
				data = listing.createData(address, dataType, length);
			}
			else {
				data = listing.createData(address, dataType);
			}
			return data;
		});
	}

	private void clear(Program p, Address a, int length) {
		tx(p, () -> {
			Listing listing = p.getListing();
			listing.clearCodeUnits(a, a.add(length), false);
		});
	}

	private Instruction createInstruction(Program program, Address atAddress) {

		return tx(program, () -> {
			Listing listing = program.getListing();
			Memory memory = program.getMemory();
			MemBuffer buf = new DumbMemBufferImpl(memory, atAddress);
			ProcessorContext context =
				new ProgramProcessorContext(program.getProgramContext(), atAddress);
			InstructionPrototype proto = program.getLanguage().parse(buf, context, false);
			Instruction createdInstruction =
				listing.createInstruction(atAddress, proto, buf, context, 0);
			return createdInstruction;
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DataTypeValidator extends TestDataProviderAndValidator {

		private Data sourceData;
		private Data destinationData;
		private DataType sourceDataType;
		private DataType originalDestinationDataType;
		private int sourceLength;
		private int originalDestinationLength;
		private ReplaceDataChoices dataTypeChoice;
		private DataTypeConflictChoices conflictChoice;
		private boolean keepExistingType;

		DataTypeValidator(Data sourceData, Data destinationData,
				ReplaceDataChoices dataTypeChoice) {

			this.sourceData = sourceData;
			this.dataTypeChoice = dataTypeChoice;
			this.sourceDataType = sourceData.getDataType();
			this.sourceDataType = sourceDataType.clone(sourceDataType.getDataTypeManager());
			this.sourceLength = sourceData.getLength();
			this.destinationData = destinationData;
			this.originalDestinationDataType = destinationData.getDataType();
			this.originalDestinationDataType =
				originalDestinationDataType.clone(originalDestinationDataType.getDataTypeManager());
			this.originalDestinationLength = destinationData.getLength();
		}

		void setConflictChoice(DataTypeConflictChoices conflictChoice) {
			this.conflictChoice = conflictChoice;
		}

		void setKeepExistingType(boolean keep) {
			this.keepExistingType = keep;
		}

		@Override
		protected Address getDestinationApplyAddress() {
			return getDestinationMatchAddress();
		}

		@Override
		protected VTMarkupItemApplyActionType getApplyAction() {
			if (dataTypeChoice == ReplaceDataChoices.EXCLUDE) {
				return null;
			}
			return REPLACE;
		}

		@Override
		protected Address getDestinationMatchAddress() {
			return destinationData.getMinAddress();
		}

		@Override
		protected Address getSourceMatchAddress() {
			return sourceData.getMinAddress();
		}

		@Override
		protected VTMarkupItem searchForMarkupItem(VTMatch match) throws Exception {
			List<VTMarkupItem> items =
				DataTypeMarkupType.INSTANCE.createMarkupItems(match.getAssociation());
			assertTrue("Did not find any data type markup items", (items.size() >= 1));
			VTMarkupItem item = items.get(0);

			return item;
		}

		@Override
		protected void assertApplied() {
			Listing listing = destinationProgram.getListing();
			Data currentDestinationData = listing.getDataAt(getDestinationApplyAddress());
			DataType currentDestinationDataType = currentDestinationData.getDataType();
			int currentDestinationLength = currentDestinationData.getLength();

			if (keepExistingType) {
				// guilty knowledge: keeping the existing type is used when the types have the same
				// data type path, but are not equivalent
				assertEquals(sourceDataType.getDataTypePath(),
					currentDestinationDataType.getDataTypePath());
			}
			else {
				assertTrue("Data type was not applied",
					sourceDataType.isEquivalent(currentDestinationDataType));
				assertTrue("Data type was not set to the source data type's size",
					sourceLength == currentDestinationLength);
			}
		}

		@Override
		protected void assertUnapplied() {
			Listing listing = destinationProgram.getListing();
			Data currentDestinationData = listing.getDataAt(getDestinationApplyAddress());
			DataType currentDestinationDataType = currentDestinationData.getDataType();
			int currentDestinationLength = currentDestinationData.getLength();
			assertTrue("Data type was not unapplied",
				originalDestinationDataType.isEquivalent(currentDestinationDataType));
			assertTrue("Data type was not reset to the original size",
				originalDestinationLength == currentDestinationLength);
		}

		@Override
		public ToolOptions getOptions() {
			ToolOptions vtOptions = super.getOptions();
			vtOptions.setEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE, dataTypeChoice);
			if (conflictChoice != null) {
				vtOptions.setEnum(VTOptionDefines.DATA_TYPE_CONFLICT_HANDLER, conflictChoice);
			}

			return vtOptions;
		}
	}
}
