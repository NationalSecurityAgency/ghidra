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
import static ghidra.feature.vt.gui.util.VTOptionDefines.FUNCTION_NAME;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionNameMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FunctionNameMarkupItemTest extends AbstractVTMarkupItemTest {

	public FunctionNameMarkupItemTest() {
		super();
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceDefault_WithDefaultDestinationName()
			throws Exception {

		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x01003f9e", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator =
			new FunctionNameValidator(sourceFunction, destinationFunction, sourceName,
				destinationName, FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyFunctionName_ReplaceDefault_WithNonDefaultDestinationName()
			throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x0100415a", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		setFunctionName(sourceFunction, sourceName);
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator =
			new FunctionNameValidator(sourceFunction, destinationFunction, sourceName,
				destinationName, FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	private void setFunctionName(Function sourceFunction, String sourceName) {
		boolean commit = true;
		int txID = sourceProgram.startTransaction("Change Source Function Name");
		try {
			sourceFunction.setName(sourceName, sourceFunction.getSymbol().getSource());
		}
		catch (Exception e) {
			commit = false;
		}
		finally {
			sourceProgram.endTransaction(txID, commit);
		}
	}

	@Test
	public void testFindAndApplyMarkupItem_ReplaceAlways_WithExistingDuplicateDestinationName()
			throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x010048a3", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.REPLACE_ALWAYS);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyFunctionName_ReplaceAlways_WithNewName() throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x0100415a", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.REPLACE_ALWAYS);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyFunctionName_Add_WithNewName() throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x0100415a", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyFunctionName_Add_WithNewName_MyPrimary() throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x0100415a", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.ADD_AS_PRIMARY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyFunctionName_Add_WithDefault() throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x01003f9e", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.ADD);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyFunctionName_IgnoreAction() throws Exception {
		Address sourceAddress = addr("0x01002cf5", sourceProgram);
		FunctionManager sourceFunctionManager = sourceProgram.getFunctionManager();
		Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);

		Address destinationAddress = addr("0x0100415a", destinationProgram);
		FunctionManager destinationFunctionManager = destinationProgram.getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);

		String sourceName = sourceFunction.getName() + getNonDynamicName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.EXCLUDE);
		doTestFindAndApplyMarkupItem(validator);
	}

////// External Function Name Tests //////

	@Test
	public void testFindAndApplyExternalMarkupItem_ReplaceDefault_WithDefaultDestinationName()
			throws Exception {

		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples");
		Function addedDestinationFunction = addDefaultExternalFunction(destinationProgram,
			"Modify Destination Program", "77db1234");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator =
			new FunctionNameValidator(sourceFunction, destinationFunction, sourceName,
				destinationName, FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyExternalFunctionName_ReplaceDefault_WithNonDefaultDestinationName()
			throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples");
		Function addedDestinationFunction =
			addExternalFunction(destinationProgram, "Modify Destination Program", "oranges");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator =
			new FunctionNameValidator(sourceFunction, destinationFunction, sourceName,
				destinationName, FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		doTestFindAndApplyMarkupItem_NoEffect(validator);
	}

	@Test
	public void testFindAndApplyExternalMarkupItem_ReplaceAlways_WithExistingDuplicateDestinationName()
			throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples");
		Function addedDestinationFunction =
			addExternalFunction(destinationProgram, "Modify Destination Program", "oranges");

		// Make a duplicate named external function.
		Function duplicateApplesFunction = null;
		int txId = destinationProgram.startTransaction("Modify Destination Program");
		boolean commit = false;
		try {
			duplicateApplesFunction =
				createExternalFunction(destinationProgram, new String[] { "user32.dll", "apples" });
			addStackParameter(duplicateApplesFunction, "P1", SourceType.USER_DEFINED,
				new DWordDataType(), 4, "Test Parameter Comment");
			addStackParameter(duplicateApplesFunction, "P2", SourceType.USER_DEFINED,
				new DWordDataType(), 8, "Test Parameter Comment");
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			destinationProgram.endTransaction(txId, commit);
		}

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.REPLACE_ALWAYS);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyExternalFunctionName_ReplaceAlways_WithNewName() throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples", "origina-apples");
		Function addedDestinationFunction = addExternalFunction(destinationProgram,
			"Modify Destination Program", "oranges", "original-oranges");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.REPLACE_ALWAYS);
		doTestFindAndApplyMarkupItem(validator);
	}

	@Test
	public void testApplyExternalFunctionName_Add_WithNewName() throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples");
		Function addedDestinationFunction =
			addExternalFunction(destinationProgram, "Modify Destination Program", "oranges");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.ADD);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testApplyExternalFunctionName_Add_WithNewName_MyPrimary() throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples");
		Function addedDestinationFunction =
			addExternalFunction(destinationProgram, "Modify Destination Program", "oranges");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.ADD_AS_PRIMARY);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testApplyExternalFunctionName_Add_WithDefault() throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "oranges");
		Function addedDestinationFunction = addDefaultExternalFunction(destinationProgram,
			"Modify Destination Program", "77db3567");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.ADD);
		doTestFindAndApplyMarkupItem_ApplyFails(validator);
	}

	@Test
	public void testApplyExternalFunctionName_IgnoreAction() throws Exception {
		Function addedSourceFunction =
			addExternalFunction(sourceProgram, "Modify Source Program", "apples");
		Function addedDestinationFunction =
			addExternalFunction(destinationProgram, "Modify Destination Program", "oranges");

		// Check the function just created.
		Function sourceFunction = getExternalFunction(sourceProgram, addedSourceFunction.getName());
		Function destinationFunction =
			getExternalFunction(destinationProgram, addedDestinationFunction.getName());
		assertEquals(addedSourceFunction.getName(), sourceFunction.getName());
		assertEquals(addedDestinationFunction.getName(), destinationFunction.getName());

		String sourceName = sourceFunction.getName();
		String destinationName = destinationFunction.getName();

		FunctionNameValidator validator = new FunctionNameValidator(sourceFunction,
			destinationFunction, sourceName, destinationName, FunctionNameChoices.EXCLUDE);
		doTestFindAndApplyMarkupItem(validator);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class FunctionNameValidator extends TestDataProviderAndValidator {

		private String sourceName;
		private String sourceOriginalName;
		private String destinationName;
		private String destinationOriginalName;
		private Function sourceFunction;
		private Function destinationFunction;
		private FunctionNameChoices functionNameChoice;

		FunctionNameValidator(Function sourceFunction, Function destinationFunction,
				String sourceName, String destinationName, FunctionNameChoices functionNameChoice) {

			this.sourceFunction = sourceFunction;
			this.destinationFunction = destinationFunction;
			this.destinationName = destinationName;
			this.sourceName = sourceName;
			if (sourceFunction.isExternal()) {
				assertTrue("Expected both functions to be external",
					destinationFunction.isExternal());
				sourceOriginalName = sourceFunction.getExternalLocation().getOriginalImportedName();
				destinationOriginalName =
					destinationFunction.getExternalLocation().getOriginalImportedName();
			}
			this.functionNameChoice = functionNameChoice;
		}

		@Override
		protected Address getDestinationApplyAddress() {
			return getDestinationMatchAddress();
		}

		@Override
		public ToolOptions getOptions() {
			ToolOptions vtOptions = super.getOptions();
			vtOptions.setEnum(FUNCTION_NAME, functionNameChoice);

			return vtOptions;
		}

		@Override
		protected VTMarkupItemApplyActionType getApplyAction() {
			if (functionNameChoice == FunctionNameChoices.EXCLUDE) {
				return null;
			}
			if (functionNameChoice == FunctionNameChoices.ADD ||
				functionNameChoice == FunctionNameChoices.ADD_AS_PRIMARY) {
				return ADD;
			}
			return REPLACE;
		}

		@Override
		protected Address getDestinationMatchAddress() {
			return destinationFunction.getEntryPoint();
		}

		@Override
		protected Address getSourceMatchAddress() {
			return sourceFunction.getEntryPoint();
		}

		@Override
		protected VTMarkupItem searchForMarkupItem(VTMatch match) throws Exception {
			List<VTMarkupItem> items =
				FunctionNameMarkupType.INSTANCE.createMarkupItems(match.getAssociation());
			assertTrue("Did not find any function name markup items", (items.size() >= 1));
			VTMarkupItem item = items.get(0);

			// we have to set the source stringable value to prevent potential name collisions
			updateSourceName();

			return item;
		}

		private void updateSourceName() {
			int id = sourceFunction.getProgram().startTransaction("update name");
			try {
				sourceFunction.setName(sourceName, SourceType.USER_DEFINED);
			}
			catch (Exception e) {
				throw new RuntimeException("Update source name failed: " + e.getMessage());
			}
			finally {
				sourceFunction.getProgram().endTransaction(id, true);
			}

		}

		@Override
		protected void assertApplied() {
			boolean sourceIsDefault = isDefaultFunctionName(sourceName, sourceFunction);
			boolean destinationIsDefault =
				isDefaultFunctionName(destinationName, destinationFunction);
			SymbolTable symbolTable = destinationFunction.getProgram().getSymbolTable();
			if (functionNameChoice == FunctionNameChoices.ADD_AS_PRIMARY) {
				if (!sourceIsDefault) {
					assertEquals("Function name was not applied", sourceName,
						destinationFunction.getName());
					if (!destinationIsDefault) {
						Symbol otherSymbol = symbolTable.getGlobalSymbol(destinationName,
							getDestinationMatchAddress());
						assertNotNull(otherSymbol);
						assertEquals(SymbolType.LABEL, otherSymbol.getSymbolType());
						assertEquals("Additional label was not applied", destinationName,
							otherSymbol.getName());
					}
				}
				else if (!destinationIsDefault) {
					assertEquals("Function name should not have been applied", destinationName,
						destinationFunction.getName());
					Symbol destinationSymbol =
						symbolTable.getGlobalSymbol(destinationName, getDestinationMatchAddress());
					assertNotNull("Expected an additional label", destinationSymbol);
					assertEquals(SymbolType.LABEL, destinationSymbol.getSymbolType());
				}
			}
			else if (functionNameChoice == FunctionNameChoices.ADD) {
				if (!destinationIsDefault) {
					assertEquals("Function name was improperly added", destinationName,
						destinationFunction.getName());
					if (!sourceIsDefault) {
						Symbol otherSymbol =
							symbolTable.getGlobalSymbol(sourceName, getDestinationMatchAddress());
						assertNotNull(otherSymbol);
						assertEquals(SymbolType.LABEL, otherSymbol.getSymbolType());
					}
				}
				else if (!sourceIsDefault) {
					assertEquals("Function name should have been applied", sourceName,
						destinationFunction.getName());
					Symbol destinationSymbol =
						symbolTable.getGlobalSymbol(destinationName, getDestinationMatchAddress());
					assertNull("Additional label was unexpected", destinationSymbol);
				}
			}
			else if (functionNameChoice == FunctionNameChoices.REPLACE_ALWAYS) {
				// TODO: Was not implemented ??  Should it be ??
				if (sourceIsDefault) {
					assertEquals("Function name was improperly renamed", destinationName,
						destinationFunction.getName());
					if (destinationFunction.isExternal()) {
						assertTrue("External Function original name was improperly renamed",
							SystemUtilities.isEqual(
								destinationFunction.getExternalLocation().getOriginalImportedName(),
								destinationOriginalName));
					}
				}
				else {
					assertEquals("Function name should have been applied", sourceName,
						destinationFunction.getName());
//					if (destinationFunction.isExternal()) {
//						// original name may get set if symbol type was IMPORTED
//					}
				}
			}
		}

		private boolean isDefaultFunctionName(String functionName, Function function) {
			String defaultFunctionName =
				SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
			return defaultFunctionName.equals(functionName);
		}

		@Override
		protected void assertUnapplied() {
			assertEquals("Function name was not unapplied", destinationName,
				destinationFunction.getName());
			if (functionNameChoice == FunctionNameChoices.ADD &&
				!isDefaultFunctionName(destinationName, destinationFunction)) {
				Symbol sourceSymbol =
					destinationFunction.getProgram().getSymbolTable().getGlobalSymbol(sourceName,
						getDestinationMatchAddress());
				assertNull(sourceSymbol);
			}
		}
	}

	Function getExternalFunction(Program program, String functionName) {

		String[] path = new String[] { "user32.dll", functionName };
		SymbolTable symbolTable = program.getSymbolTable();
		int nameIndex = path.length - 1;

		Symbol librarySymbol = symbolTable.getLibrarySymbol(path[0]);
		Library externalLibrary = (Library) librarySymbol.getObject();

		Namespace currentNamespace = externalLibrary;
		for (int i = 1; i < nameIndex; i++) {
			Symbol nextNamespaceSymbol = getUniqueSymbol(program, path[i], currentNamespace);
			currentNamespace = (Namespace) nextNamespaceSymbol.getObject();
		}

		Symbol functionSymbol = getUniqueSymbol(program, path[nameIndex], currentNamespace);
		if (functionSymbol == null) {
			return null;
		}
		SymbolType functionSymbolType = functionSymbol.getSymbolType();
		assertEquals(SymbolType.FUNCTION, functionSymbolType);
		Function function = (Function) functionSymbol.getObject();
		return function;
	}

	Function createExternalFunction(Program program, String[] path)
			throws DuplicateNameException, InvalidInputException {
		return createExternalFunction(program, path, null, null, null, SourceType.USER_DEFINED);
	}

	Function createExternalFunction(Program program, String[] path, Address address)
			throws DuplicateNameException, InvalidInputException {
		return createExternalFunction(program, path, null, address, null, SourceType.USER_DEFINED);
	}

	Function createExternalFunction(Program program, String[] path, DataType returnType)
			throws DuplicateNameException, InvalidInputException {
		return createExternalFunction(program, path, null, null, returnType,
			SourceType.USER_DEFINED);
	}

	Function createExternalFunction(Program program, String[] path, String originalName,
			Address memoryAddress, DataType returnType, SourceType sourceType)
			throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		ExternalManager externalManager = program.getExternalManager();
		int nameIndex = path.length - 1;

		Library externalLibrary;
		Symbol librarySymbol = symbolTable.getLibrarySymbol(path[0]);
		if (librarySymbol != null) {
			externalLibrary = (Library) librarySymbol.getObject();
		}
		else {
			externalLibrary = symbolTable.createExternalLibrary(path[0], sourceType);
		}

		Namespace currentNamespace = externalLibrary;
		for (int i = 1; i < nameIndex; i++) {
			Symbol nextNamespaceSymbol = getUniqueSymbol(program, path[i], currentNamespace);
			if (nextNamespaceSymbol != null) {
				currentNamespace = (Namespace) nextNamespaceSymbol.getObject();
			}
			else {
				currentNamespace =
					symbolTable.createNameSpace(currentNamespace, path[i], sourceType);
			}
		}

		ExternalLocation externalLocation = null;
		if (originalName != null) {
			externalLocation = externalManager.addExtFunction(externalLibrary, originalName,
				memoryAddress, SourceType.IMPORTED);
		}
		if (externalLocation != null) {
			externalLocation.setName(currentNamespace, path[nameIndex], sourceType);
		}
		else {
			externalLocation = externalManager.addExtFunction(currentNamespace, path[nameIndex],
				memoryAddress, sourceType);
		}
		Function function = externalLocation.getFunction();
		assertNotNull(function);

		if (returnType != null) {
			function.setReturnType(returnType, sourceType);
		}

		return function;
	}

	Parameter addStackParameter(Function function, String name, SourceType sourceType,
			DataType dataType, int stackOffset, String comment)
			throws InvalidInputException, DuplicateNameException {
		Parameter parameter1 =
			new ParameterImpl(name, dataType, stackOffset, function.getProgram());
		parameter1.setComment(comment);
		return function.addParameter(parameter1, sourceType);
	}

	void checkDataType(DataType expectedDataType, DataType actualDataType) {
		String failureMessage = "Expected external data type '" + expectedDataType.getName() +
			"' but was '" + ((actualDataType != null) ? actualDataType.getName() : null) + "'";
		assertTrue(failureMessage, expectedDataType.isEquivalent(actualDataType));
	}

	private Function addExternalFunction(Program program, String txDescription,
			String functionName) {
		return addExternalFunction(program, txDescription, functionName, null);
	}

	private Function addExternalFunction(Program program, String txDescription, String functionName,
			String originalName) {
		Function function = null;
		int txId = program.startTransaction(txDescription);
		boolean commit = false;
		try {
			function = createExternalFunction(program, new String[] { "user32.dll", functionName },
				originalName, null, null, SourceType.USER_DEFINED);
			addStackParameter(function, "P1", SourceType.USER_DEFINED, new DWordDataType(), 4,
				"Test Parameter Comment");
			addStackParameter(function, "P2", SourceType.USER_DEFINED, new DWordDataType(), 8,
				"Test Parameter Comment");
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}
		return function;
	}

	private Function addDefaultExternalFunction(Program program, String txDescription,
			String memAddress) {
		Function function = null;
		int txId = program.startTransaction(txDescription);
		boolean commit = false;
		try {
			function = createExternalFunction(program, new String[] { "user32.dll", null },
				addr(memAddress, program));
			addStackParameter(function, "P1", SourceType.USER_DEFINED, new DWordDataType(), 4,
				"Test Parameter Comment");
			addStackParameter(function, "P2", SourceType.USER_DEFINED, new DWordDataType(), 8,
				"Test Parameter Comment");
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}
		return function;
	}
}
