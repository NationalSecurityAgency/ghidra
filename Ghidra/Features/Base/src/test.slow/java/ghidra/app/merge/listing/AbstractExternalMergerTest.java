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

import java.awt.Component;
import java.awt.Window;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

import org.junit.Assert;

import generic.test.TestUtils;
import ghidra.app.cmd.function.AddRegisterParameterCommand;
import ghidra.app.cmd.function.AddStackParameterCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.symbol.LibrarySymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public abstract class AbstractExternalMergerTest extends AbstractListingMergeManagerTest {

	static final String KEEP_BOTH_BUTTON = ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME;
	static final String MERGE_BOTH_BUTTON = ExternalFunctionMerger.MERGE_BOTH_BUTTON_NAME;

	public AbstractExternalMergerTest() {
		super();
	}

	ExternalLocation createExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString, DataType dataType,
			SourceType sourceType) {
		Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Library externalLibrary = symbolTable.createExternalLibrary(library, sourceType);
			ExternalLocation externalLocation =
				externalManager.addExtLocation(externalLibrary, label, address, sourceType);
			if (dataType != null) {
				externalLocation.setDataType(dataType);
			}

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(false, externalLocation.isFunction());

		assertEquals(library + "::" + label, externalLocation.toString());
		assertEquals(address, externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == sourceType);
		DataType extDataType = externalLocation.getDataType();
		if (dataType == null) {
			assertNull(extDataType);
		}
		else {
			assertNotNull(extDataType);
			assertTrue(extDataType.isEquivalent(dataType));
		}
		return externalLocation;
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 */
	void removeExternalLabel(ProgramDB program, String transactionDescription, String library,
			String label) {
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			program.getSymbolTable().removeSymbolSpecial(externalLocation.getSymbol());

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNull(externalLocation);
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param addressAsString
	 * @param sourceType
	 * @return
	 */
	ExternalLocation createExternalFunction(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString, SourceType sourceType) {
		Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Library externalLibrary = symbolTable.createExternalLibrary(library, sourceType);
			ExternalLocation externalLocation =
				externalManager.addExtFunction(externalLibrary, label, address, sourceType);
			assertNotNull(externalLocation);
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(true, externalLocation.isFunction());

		assertEquals(library + "::" + label, externalLocation.toString());
		assertEquals(address, externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == sourceType);
		DataType extDataType = externalLocation.getDataType();
		assertNull(extDataType);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(0, function.getParameterCount());
		return externalLocation;
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param addressAsString
	 */
	void removeExternalFunctionLocation(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString) {
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			if (!externalLocation.isFunction()) {
				Assert.fail(externalLocation.getLabel() + " is not a function.");
			}
			Symbol externalSymbol = externalLocation.getSymbol();
			boolean delete = externalSymbol.delete();
			assertTrue(delete);
			commit = true;

			Symbol s = getUniqueSymbol(program, library, program.getGlobalNamespace());
			if (s instanceof LibrarySymbol) {
				Symbol symbol = getUniqueSymbol(program, label, (Namespace) s.getObject());
				symbol.delete();
			}
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s = symbolTable.getLibrarySymbol(library);
		if (s instanceof LibrarySymbol) {
			Symbol symbol = getUniqueSymbol(program, label, (Namespace) s.getObject());
			assertNull(symbol);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNull(externalLocation);
		FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();
		assertEquals(false, externalFunctions.hasNext());
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param addressAsString
	 */
	void changeExternalFunctionIntoExternalLabel(Program program, String[] path) {
		Function externalFunction = getExternalFunction(program, path);

		int txId = program.startTransaction("Changing external function into an external label.");
		boolean commit = false;
		try {
			Symbol externalSymbol = externalFunction.getSymbol();
			boolean delete = externalSymbol.delete();
			assertTrue(delete);
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		ExternalLocation externalLocation = getExternalLocation(program, path);
		assertNotNull(externalLocation);
		assertFalse(externalLocation.isFunction());
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param addressAsString
	 */
	void setAddressForExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString) {
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
			externalLocation.setLocation(externalLocation.getLabel(), address,
				externalLocation.getSource());

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		Address address = externalLocation.getAddress();
		assertEquals(addressAsString, (address != null) ? address.toString() : null);
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 */
	void removeAddressFromExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label) {
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			externalLocation.setLocation(externalLocation.getLabel(), null,
				externalLocation.getSource());

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		assertNull(externalLocation.getAddress());
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 */
	void changeMemAddressForExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, String changeAddressAsString) {
		Address changeAddress =
			(changeAddressAsString != null) ? addr(program, changeAddressAsString) : null;

		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			externalLocation.setLocation(externalLocation.getLabel(), changeAddress,
				externalLocation.getSource());

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		assertEquals(changeAddress, externalLocation.getAddress());
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param addressAsString
	 * @param externalDataType
	 */
	void setDataTypeForExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString, DataType externalDataType) {
		Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			externalLocation.setDataType(externalDataType);

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		assertEquals(address, externalLocation.getAddress());
		DataType dataType = externalLocation.getDataType();
		assertTrue(dataType.isEquivalent(externalDataType));
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param addressAsString
	 */
	void removeDataTypeFromExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString) {
		Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			externalLocation.setDataType(null);

			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		assertEquals(address, externalLocation.getAddress());
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 * @param externalSourceType
	 */
	void setSourceTypeForExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, SourceType externalSourceType) {
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			externalLocation.setLocation(externalLocation.getLabel(), externalLocation.getAddress(),
				externalSourceType);
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		SourceType sourceType = externalLocation.getSource();
		assertTrue(sourceType == externalSourceType);
	}

	/**
	 *
	 * @param program
	 * @param transactionDescription
	 * @param library
	 * @param label
	 */
	void changeExternalLabelIntoFunction(ProgramDB program, String transactionDescription,
			String library, String label) {
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			ExternalLocation externalLocation =
				externalManager.getUniqueExternalLocation(library, label);
			assertNotNull(externalLocation);
			externalLocation.createFunction();
			commit = true;
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txId, commit);
		}

		assertTrue(externalManager.contains(library));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation(library, label);
		assertNotNull(externalLocation);
		assertEquals(library + "::" + label, externalLocation.toString());
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
	}

	/**
	 *
	 * @param externalLocation
	 * @param expectedAddress
	 */
	void checkExternalAddress(ExternalLocation externalLocation, String expectedAddress) {
		Address address = externalLocation.getAddress();
		String addressString = (address != null) ? address.toString() : null;
		String failureMessage =
			"Expected external address '" + expectedAddress + "' but was '" + addressString + "'";
		assertEquals(failureMessage, expectedAddress, addressString);
	}

	/**
	 *
	 * @param externalLocation
	 * @param expectedSourceType
	 */
	void checkExternalSourceType(ExternalLocation externalLocation, SourceType expectedSourceType) {
		SourceType sourceType = externalLocation.getSource();
		String failureMessage =
			"Expected external source type '" + expectedSourceType.getDisplayString() +
				"' but was '" + sourceType.getDisplayString() + "'";
		assertEquals(failureMessage, expectedSourceType, sourceType);
	}

	/**
	 *
	 * @param externalLocation
	 * @param expectedDataType
	 */
	void checkExternalDataType(ExternalLocation externalLocation, DataType expectedDataType) {
		DataType dataType = externalLocation.getDataType();
		String failureMessage = "Expected external data type '" + expectedDataType.getName() +
			"' but was '" + ((dataType != null) ? dataType.getName() : null) + "'";
		assertTrue(failureMessage, expectedDataType.isEquivalent(dataType));
	}

	void checkDataType(DataType expectedDataType, DataType actualDataType) {
		String failureMessage = "Expected external data type '" + expectedDataType.getName() +
			"' but was '" + ((actualDataType != null) ? actualDataType.getName() : null) + "'";
		assertTrue(failureMessage, expectedDataType.isEquivalent(actualDataType));
	}

	/**
	 *
	 * @param function
	 * @param expectedDataType
	 */
	void checkFunctionReturnType(Function function, DataType expectedDataType) {
		DataType functionReturnType = function.getReturnType();
		String failureMessage = "Expected return type '" + expectedDataType.getName() +
			"' but was '" + functionReturnType.getName() + "'";
		assertTrue(failureMessage, expectedDataType.isEquivalent(functionReturnType));
	}

	/**
	 *
	 * @param parameter
	 * @param expectedDataType
	 */
	void checkParameterDataType(Parameter parameter, DataType expectedDataType) {
		DataType parameterDataType = parameter.getDataType();
		String failureMessage =
			"Expected data type '" + expectedDataType.getName() + "' for parameter " +
				(parameter.getOrdinal() + 1) + " but was '" + parameterDataType.getName() + "'";
		assertTrue(failureMessage, expectedDataType.isEquivalent(parameterDataType));
	}

	/**
	 *
	 * @param programVersion
	 * @param externalLocationPathName
	 * @param conflictNumber
	 * @param totalNumberOfConflicts
	 * @throws Exception
	 */
	void checkExternalPanelInfo(final String programVersion, final String externalLocationPathName,
			final int conflictNumber, final int totalNumberOfConflicts) throws Exception {
		waitForPrompting();
		Component mergePanel = getMergePanel(ExternalConflictInfoPanel.class);
		Window window = windowForComponent(mergePanel);
		JComponent comp = findComponent(window, ExternalConflictInfoPanel.class);
		assertNotNull(comp);
		Border border = comp.getBorder();
		String title = ((TitledBorder) border).getTitle();
		assertEquals("Resolve External Location Conflict", title);
		ExternalConflictInfoPanel panel = (ExternalConflictInfoPanel) comp;
		String versionTitle = (String) TestUtils.getInstanceField("versionTitle", panel);
		assertEquals(programVersion, versionTitle);
		String labelPathName = (String) TestUtils.getInstanceField("labelPathName", panel);
		assertEquals(externalLocationPathName, labelPathName);
		int conflictNum = (Integer) TestUtils.getInstanceField("conflictNum", panel);
		assertEquals(conflictNumber, conflictNum);
		int totalConflicts = (Integer) TestUtils.getInstanceField("totalConflicts", panel);
		assertEquals(totalNumberOfConflicts, totalConflicts);
	}

	/**
	 * Changes the function's parameter indicated by index to be a register
	 * parameter with the indicated register.
	 * @param func the function
	 * @param index the index of an existing parameter
	 * @param reg the new register for this parameter
	 */
	void changeToRegisterParameter(Function func, int index, Register reg) {
		Parameter p = func.getParameter(index);
		String name = p.getName();
		DataType dt = p.getDataType();
		String comment = p.getComment();
		func.removeParameter(index);
		func.setCustomVariableStorage(true);
		AddRegisterParameterCommand cmd =
			new AddRegisterParameterCommand(func, reg, null, dt, index, SourceType.USER_DEFINED);
		cmd.applyTo(func.getProgram());
		p = func.getParameter(index);
		if (!isDefaultParamName(name)) {
			try {
				p.setName(name, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}
			catch (InvalidInputException e) {
				Assert.fail(e.getMessage());
			}
		}
		if (comment != null) {
			p.setComment(comment);
		}
	}

	/**
	 * @param name the parameter name
	 * @return true if name is null or a default parameter name.
	 */
	boolean isDefaultParamName(String name) {
		if (name == null) {
			return true;
		}
		if (name.startsWith(Function.DEFAULT_PARAM_PREFIX)) {
			String num = name.substring(Function.DEFAULT_PARAM_PREFIX.length());
			try {
				Integer.parseInt(num);
				return true;
			}
			catch (NumberFormatException e1) {
				// Do nothing so returns false;
			}
		}
		return false;
	}

	/**
	 * Changes the function's parameter indicated by index to be a stack
	 * parameter with the indicated stack offset.
	 * @param func the function
	 * @param index the index of an existing parameter
	 * @param stackOffset the stack offset for this parameter
	 */
	void changeToStackParameter(Function func, int index, int stackOffset) {
		Parameter p = func.getParameter(index);
		String name = p.getName();
		DataType dt = p.getDataType();
		String comment = p.getComment();
		func.removeParameter(index);
		AddStackParameterCommand cmd = new AddStackParameterCommand(func, stackOffset, null, dt,
			index, SourceType.USER_DEFINED);
		cmd.applyTo(func.getProgram());
		p = func.getParameter(index);
		if (!isDefaultParamName(name)) {
			try {
				p.setName(name, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}
			catch (InvalidInputException e) {
				Assert.fail(e.getMessage());
			}
		}
		if (comment != null) {
			p.setComment(comment);
		}
	}

	Function createExternalFunction(final Program program, final String[] path)
			throws DuplicateNameException, InvalidInputException {
		return createExternalFunction(program, path, null, null, SourceType.USER_DEFINED);
	}

	Function createExternalFunction(final Program program, final String[] path,
			final Address address) throws DuplicateNameException, InvalidInputException {
		return createExternalFunction(program, path, address, null, SourceType.USER_DEFINED);
	}

	Function createExternalFunction(final Program program, final String[] path,
			final DataType returnType) throws DuplicateNameException, InvalidInputException {
		return createExternalFunction(program, path, null, returnType, SourceType.USER_DEFINED);
	}

	Function createExternalFunction(final Program program, final String[] path,
			final Address memoryAddress, final DataType returnType, final SourceType sourceType)
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

		ExternalLocation externalLocation = externalManager.addExtFunction(currentNamespace,
			path[nameIndex], memoryAddress, sourceType);

		Function function = externalLocation.getFunction();
		assertNotNull(function);

		if (returnType != null) {
			function.setReturnType(returnType, sourceType);
		}

		return function;
	}

	ExternalLocation createExternalLabel(final Program program, final String[] path,
			final Address memoryAddress, final SourceType sourceType)
			throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		ExternalManager externalManager = program.getExternalManager();
		int nameIndex = path.length - 1;

		Library externalLibrary;
		Symbol librarySymbol = getUniqueSymbol(program, path[0], program.getGlobalNamespace());
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

		ExternalLocation externalLocation = externalManager.addExtLocation(currentNamespace,
			path[nameIndex], memoryAddress, sourceType);

		return externalLocation;
	}

	Namespace createExternalNamespace(final Program program, final String[] path,
			final SourceType sourceType) throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		int namespaceIndex = path.length;

		Library externalLibrary;
		Symbol librarySymbol = getUniqueSymbol(program, path[0], program.getGlobalNamespace());
		if (librarySymbol != null) {
			externalLibrary = (Library) librarySymbol.getObject();
		}
		else {
			externalLibrary = symbolTable.createExternalLibrary(path[0], sourceType);
		}

		Namespace currentNamespace = externalLibrary;
		for (int i = 1; i < namespaceIndex; i++) {
			Symbol nextNamespaceSymbol = getUniqueSymbol(program, path[i], currentNamespace);
			if (nextNamespaceSymbol != null) {
				currentNamespace = (Namespace) nextNamespaceSymbol.getObject();
			}
			else {
				currentNamespace =
					symbolTable.createNameSpace(currentNamespace, path[i], sourceType);
			}
		}

		return currentNamespace;
	}

	Parameter addStackParameter(Function function, String name, SourceType sourceType,
			DataType dataType, int stackOffset, String comment)
			throws InvalidInputException, DuplicateNameException {
		Parameter parameter1 =
			new ParameterImpl(name, dataType, stackOffset, function.getProgram());
		parameter1.setComment(comment);
		return function.addParameter(parameter1, sourceType);
	}

	Parameter addParameter(Function function, String name, SourceType sourceType, DataType dataType,
			String comment) throws InvalidInputException, DuplicateNameException {
		Parameter parameter1 = new ParameterImpl(name, dataType, function.getProgram());
		parameter1.setComment(comment);
		return function.addParameter(parameter1, sourceType);
	}

	Function getExternalFunction(Program program, String[] path) {

		SymbolTable symbolTable = program.getSymbolTable();
		int nameIndex = path.length - 1;

		Symbol librarySymbol = symbolTable.getLibrarySymbol(path[0]);
		SymbolType librarySymbolType = librarySymbol.getSymbolType();
		assertEquals(SymbolType.LIBRARY, librarySymbolType);
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

	ExternalLocation getExternalLocation(Program program, String[] path) {
		int nameIndex = path.length - 1;
		Namespace namespace = getExternalNamespace(program, path, path.length - 1);

		List<Symbol> symbols = program.getSymbolTable().getSymbols(path[nameIndex], namespace);
		if (symbols.size() != 1) {
			return null;
		}
		ExternalManager externalManager = program.getExternalManager();
		return externalManager.getExternalLocation(symbols.get(0));
	}

	Namespace getExternalNamespace(Program program, String[] path) {
		return getExternalNamespace(program, path, path.length);
	}

	Namespace getExternalNamespace(Program program, String[] path, int pathLength) {

		SymbolTable symbolTable = program.getSymbolTable();

		Symbol librarySymbol = symbolTable.getLibrarySymbol(path[0]);
		SymbolType librarySymbolType = librarySymbol.getSymbolType();
		assertEquals(SymbolType.LIBRARY, librarySymbolType);
		Library externalLibrary = (Library) librarySymbol.getObject();

		Namespace currentNamespace = externalLibrary;
		for (int i = 1; i < pathLength; i++) {
			currentNamespace = findExternalNamespaceSymbol(symbolTable, path[i], currentNamespace);
			if (currentNamespace == null) {
				return null;
			}
		}
		return currentNamespace;
	}

	private Namespace findExternalNamespaceSymbol(SymbolTable symbolTable, String name,
			Namespace currentNamespace) {
		List<Symbol> symbols = symbolTable.getSymbols(name, currentNamespace);
		for (Symbol symbol : symbols) {
			Object object = symbol.getObject();
			if (object instanceof Namespace) {
				Namespace namespace = (Namespace) object;
				if (namespace.isExternal()) {
					return namespace;
				}
			}
		}
		return null;
	}
}
