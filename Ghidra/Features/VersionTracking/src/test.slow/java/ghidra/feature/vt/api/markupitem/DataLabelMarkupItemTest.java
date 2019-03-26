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

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.ADD;
import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.REPLACE;
import static ghidra.feature.vt.db.VTTestUtils.addr;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.LabelMarkupType;
import ghidra.feature.vt.api.stringable.MultipleSymbolStringable;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.LabelChoices;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

public class DataLabelMarkupItemTest extends AbstractVTMarkupItemTest {

	@Test
	public void testFindAndApplyMarkupItem_Add_MultipleSourceLabel_WithNoExistingDestinationLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol2 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol3 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[3];
		sourceSymbols[0] = sourceSymbol1;
		sourceSymbols[1] = sourceSymbol2;
		sourceSymbols[2] = sourceSymbol3;

		Symbol[] destinationSymbols = null;

		Symbol[] expectedSymbols = sourceSymbols;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceAll_MultipleSourceLabel_WithNoExistingDestinationLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol2 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol3 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[3];
		sourceSymbols[0] = sourceSymbol1;
		sourceSymbols[1] = sourceSymbol2;
		sourceSymbols[2] = sourceSymbol3;

		Symbol[] destinationSymbols = null;

		Symbol[] expectedSymbols = sourceSymbols;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_ALL);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_Add_MultipleSourceLabel_WithSingleExistingDuplicateLabel()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol2 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol3 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[3];
		sourceSymbols[0] = sourceSymbol1;
		sourceSymbols[1] = sourceSymbol2;
		sourceSymbols[2] = sourceSymbol3;

		// put label with duplicate name at address other than applied address
		Address someOtherAddress = labelAddress.subtract(1);
		addLabel(sourceSymbol3.getName(), someOtherAddress, destinationProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);
		Symbol[] destinationSymbols = new Symbol[] { destinationSymbol1 };

		Symbol[] expectedSymbols = sourceSymbols;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_Add_MultipleSourceLabels_WithMultipleExistingDestinationLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol2 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol3 = addLabel(labelAddress, sourceProgram);

		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol2 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol3 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[3];
		sourceSymbols[0] = sourceSymbol1;
		sourceSymbols[1] = sourceSymbol2;
		sourceSymbols[2] = sourceSymbol3;

		Symbol[] destinationSymbols = new Symbol[3];
		destinationSymbols[0] = destinationSymbol1;
		destinationSymbols[1] = destinationSymbol2;
		destinationSymbols[2] = destinationSymbol3;

		Symbol[] expectedSymbols = new Symbol[6];
		expectedSymbols[0] = destinationSymbol1;
		expectedSymbols[1] = destinationSymbol2;
		expectedSymbols[2] = destinationSymbol3;
		expectedSymbols[3] = sourceSymbol1;
		expectedSymbols[4] = sourceSymbol2;
		expectedSymbols[5] = sourceSymbol3;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceAll_MultipleSourceLabels_WithMultipleExistingDestinationLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol2 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol3 = addLabel(labelAddress, sourceProgram);

		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol2 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol3 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[3];
		sourceSymbols[0] = sourceSymbol1;
		sourceSymbols[1] = sourceSymbol2;
		sourceSymbols[2] = sourceSymbol3;

		Symbol[] destinationSymbols = new Symbol[3];
		destinationSymbols[0] = destinationSymbol1;
		destinationSymbols[1] = destinationSymbol2;
		destinationSymbols[2] = destinationSymbol3;

		Symbol[] expectedSymbols = new Symbol[3];
		expectedSymbols[0] = sourceSymbol1;
		expectedSymbols[1] = sourceSymbol2;
		expectedSymbols[2] = sourceSymbol3;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_ALL);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_Add_SingleSourceLabel_WithMultipleExistingLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);

		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol2 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol3 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = new Symbol[3];
		destinationSymbols[0] = destinationSymbol1;
		destinationSymbols[1] = destinationSymbol2;
		destinationSymbols[2] = destinationSymbol3;

		Symbol[] expectedSymbols = new Symbol[4];
		expectedSymbols[0] = destinationSymbol1;
		expectedSymbols[1] = destinationSymbol2;
		expectedSymbols[2] = destinationSymbol3;
		expectedSymbols[3] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceAll_SingleSourceLabel_WithMultipleExistingLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);

		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol2 = addLabel(labelAddress, destinationProgram);
		Symbol destinationSymbol3 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = new Symbol[3];
		destinationSymbols[0] = destinationSymbol1;
		destinationSymbols[1] = destinationSymbol2;
		destinationSymbols[2] = destinationSymbol3;

		Symbol[] expectedSymbols = new Symbol[1];
		expectedSymbols[0] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_ALL);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_Add_SingleSourceLabel_WithNoExistingDestinationLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = null;

		Symbol[] expectedSymbols = new Symbol[1];
		expectedSymbols[0] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceAll_SingleSourceLabel_WithNoExistingDestinationLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = null;

		Symbol[] expectedSymbols = new Symbol[1];
		expectedSymbols[0] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_ALL);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceDefault_SingleSourceLabel_WithSingleExistingDefaultLabel()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol destinationSymbol1 = addDefaultLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = new Symbol[] { destinationSymbol1 };

		Symbol[] expectedSymbols = new Symbol[1];
		expectedSymbols[0] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_ALL);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_Add_SingleSourceLabel_WithSingleExistingDestinationLabel()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = new Symbol[1];
		destinationSymbols[0] = destinationSymbol1;

		Symbol[] expectedSymbols = new Symbol[2];
		expectedSymbols[0] = destinationSymbol1;
		expectedSymbols[1] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceAll_SingleSourceLabel_WithSingleExistingDestinationLabel()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = new Symbol[1];
		destinationSymbols[0] = destinationSymbol1;

		Symbol[] expectedSymbols = new Symbol[1];
		expectedSymbols[0] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_ALL);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_Add_SingleSourceLabel_WithSingleExistingDuplicateLabels()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		// put label with duplicate name at address other than applied address
		Address someOtherAddress = labelAddress.subtract(1);
		addLabel(sourceSymbol1.getName(), someOtherAddress, destinationProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);
		Symbol[] destinationSymbols = new Symbol[] { destinationSymbol1 };

		Symbol[] expectedSymbols = null;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.ADD);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceDefault_SingleSourceLabel_WithSingleExistingNonDefaultLabel()
			throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol destinationSymbol1 = addLabel(labelAddress, destinationProgram);

		Symbol[] sourceSymbols = new Symbol[1];
		sourceSymbols[0] = sourceSymbol1;

		Symbol[] destinationSymbols = new Symbol[1];
		destinationSymbols[0] = destinationSymbol1;

		Symbol[] expectedSymbols = new Symbol[2];
		expectedSymbols[0] = destinationSymbol1; // the value should not be replaced
		expectedSymbols[1] = sourceSymbol1;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.REPLACE_DEFAULT_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testFindAndApplyMarkupItem_IgnoreAction() throws Exception {
		Address labelAddress = addr("0x010074be", sourceProgram);

		Symbol sourceSymbol1 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol2 = addLabel(labelAddress, sourceProgram);
		Symbol sourceSymbol3 = addLabel(labelAddress, sourceProgram);

		Symbol[] sourceSymbols = new Symbol[3];
		sourceSymbols[0] = sourceSymbol1;
		sourceSymbols[1] = sourceSymbol2;
		sourceSymbols[2] = sourceSymbol3;

		Symbol[] destinationSymbols = null;

		Symbol[] expectedSymbols = null;

		LabelValidator validator = new LabelValidator("0x010074be", "0x010074be", labelAddress,
			sourceSymbols, destinationSymbols, expectedSymbols, LabelChoices.EXCLUDE);
		doTestFindAndApplyMarkupItem(validator);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Symbol addLabel(Address address, Program program) throws InvalidInputException {
		return addLabel("test" + getNonDynamicName(), address, program);
	}

	private Symbol addLabel(String name, Address address, Program program)
			throws InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Label");
			return symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private Symbol addDefaultLabel(Address address, Program program) {

		SymbolTable symbolTable = program.getSymbolTable();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Label");
			ReferenceManager referenceManager = program.getReferenceManager();
			referenceManager.addMemoryReference(address, address, RefType.READ,
				SourceType.USER_DEFINED, 0);
			return symbolTable.getPrimarySymbol(address);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	private class LabelValidator extends TestDataProviderAndValidator {

		private final Address labelAddress;
		private final Address sourceFunctionAddress;
		private final Address destinationFunctionAddress;
		private final Symbol[] sourceSymbols;
		private final Symbol[] destinationSymbols;
		private final Symbol[] expectedSymbols;
		private LabelChoices labelChoice;

		LabelValidator(String sourceFunctionAddressString, String destinationFunctionsAddressString,
				Address labelAddress, Symbol[] sourceSymbols, Symbol[] destinationSymbols,
				Symbol[] expectedSymbols, LabelChoices labelChoice) {
			this.sourceSymbols = sourceSymbols;
			this.destinationSymbols = destinationSymbols;
			this.expectedSymbols = expectedSymbols;
			this.labelChoice = labelChoice;
			this.sourceFunctionAddress = addr(sourceFunctionAddressString, sourceProgram);
			this.destinationFunctionAddress =
				addr(destinationFunctionsAddressString, destinationProgram);
			this.labelAddress = labelAddress;
		}

		@Override
		protected Address getDestinationApplyAddress() {
			return labelAddress;
		}

		@Override
		protected VTMarkupItemApplyActionType getApplyAction() {
			switch (labelChoice) {
				case EXCLUDE:
					return null;
				case REPLACE_ALL:
				case REPLACE_DEFAULT_ONLY:
					return REPLACE;
				case ADD:
				case ADD_AS_PRIMARY:
				default:
					return ADD;
			}
		}

		@Override
		protected Address getDestinationMatchAddress() {
			return destinationFunctionAddress;
		}

		@Override
		protected Address getSourceMatchAddress() {
			return sourceFunctionAddress;
		}

		@Override
		protected VTMarkupItem searchForMarkupItem(VTMatch match) throws Exception {
			List<VTMarkupItem> items =
				LabelMarkupType.INSTANCE.createMarkupItems(match.getAssociation());
			assertTrue("Did not find any label markup items", (items.size() >= 1));
			VTMarkupItem item = items.get(0);

			// we have to set the source and destination values to control the output of our tests
			MultipleSymbolStringable sourceStringable = null;
			if (sourceSymbols != null) {
				sourceStringable = new MultipleSymbolStringable(sourceSymbols);
			}

			Object obj = getInstanceField("markupItemStorage", item);
			setInstanceField("sourceValue", obj, sourceStringable);

			return item;
		}

		@Override
		protected void assertApplied() {
			SymbolTable symbolTable = destinationProgram.getSymbolTable();
			Symbol[] newSymbols = symbolTable.getSymbols(labelAddress);

			Symbol[] expectedSymbolsForTest = expectedSymbols;
			if (expectedSymbolsForTest == null) {
				expectedSymbolsForTest = new Symbol[0];
			}

			assertArraysEqualOrdered(
				"New symbol does not match the source symbol at " + labelAddress,
				expectedSymbolsForTest, newSymbols);
		}

		@Override
		protected void assertUnapplied() {
			SymbolTable symbolTable = destinationProgram.getSymbolTable();
			Symbol[] newSymbols = symbolTable.getSymbols(labelAddress);
			if (newSymbols.length == 0) {
				newSymbols = null;
			}
			assertArraysEqualOrdered(
				"Symbols should not have been applied--they should not match at " + labelAddress,
				destinationSymbols, newSymbols);
		}

		@Override
		public ToolOptions getOptions() {
			ToolOptions vtOptions = super.getOptions();
			vtOptions.setEnum(VTOptionDefines.LABELS, labelChoice);

			return vtOptions;
		}
	}

}
