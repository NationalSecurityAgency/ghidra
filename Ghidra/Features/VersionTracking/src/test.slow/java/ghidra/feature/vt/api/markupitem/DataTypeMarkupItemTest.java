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

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.REPLACE;
import static ghidra.feature.vt.db.VTTestUtils.addr;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.DataTypeMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.ReplaceDataChoices;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class DataTypeMarkupItemTest extends AbstractVTMarkupItemTest {

	public DataTypeMarkupItemTest() {
		super();
	}

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

//==================================================================================================
// Private Methods
//==================================================================================================

	private Data setDataType(Program program, Address address, DataType dataType, int length) {

		int txID = program.startTransaction("Change Data Type");
		boolean commit = false;
		try {
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
			commit = true;
			return data;
		}
		catch (Exception e) {
			// Commit is false by default so nothing else to do.
			return null;
		}
		finally {
			program.endTransaction(txID, commit);
		}
	}

	private Instruction createInstruction(Program program, Address atAddress) {

		int txID = program.startTransaction("Create Instruction");
		boolean commit = false;
		try {
			Listing listing = program.getListing();
			Memory memory = program.getMemory();
			MemBuffer buf = new DumbMemBufferImpl(memory, atAddress);
			ProcessorContext context =
				new ProgramProcessorContext(program.getProgramContext(), atAddress);
			InstructionPrototype proto = program.getLanguage().parse(buf, context, false);
			Instruction createdInstruction =
				listing.createInstruction(atAddress, proto, buf, context);
			commit = true;
			return createdInstruction;
		}
		catch (Exception e) {
			// Commit is false by default so nothing else to do.
			return null;
		}
		finally {
			program.endTransaction(txID, commit);
		}
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
			assertTrue("Data type was not applied",
				sourceDataType.isEquivalent(currentDestinationDataType));
			assertTrue("Data type was not set to the source data type's size",
				sourceLength == currentDestinationLength);
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

			return vtOptions;
		}
	}
}
