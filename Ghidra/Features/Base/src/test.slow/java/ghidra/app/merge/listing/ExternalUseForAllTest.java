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

import javax.swing.AbstractButton;
import javax.swing.JCheckBox;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

public class ExternalUseForAllTest extends AbstractExternalMergerTest {

	public ExternalUseForAllTest() {
		super();
	}

	private void setupRemoveUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);

				createExternalLabel(program, "Modify Original Program", "user32.dll", "Green",
					"77db1120", new FloatDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setLocation("Red", externalLocation.getAddress(),
						externalLocation.getSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Red");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Red", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new DWordDataType()));

				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Green");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalLabel(program, "Modify Private Program", "user32.dll", "Blue");

				// change DataType
				int txId = program.startTransaction("Modify Private Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Green");
					assertNotNull(externalLocation);
					externalLocation.setLocation("Brown", externalLocation.getAddress(),
						externalLocation.getSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Brown");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Brown", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new FloatDataType()));

			}
		});
	}

	@Test
	public void testExternalRemoveConflictDontUseForAll() throws Exception {

		setupRemoveUseForAll();

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Remove Conflict", LATEST_BUTTON);// Blue removed or changed to Red
		chooseRadioButton("Resolve External Remove Conflict", MY_BUTTON);// Green removed or changed to Brown
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Red", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Brown");
		assertNotNull(externalLocation2);
		assertEquals("user32.dll::Brown", externalLocation2.toString());
		assertEquals(addr(resultProgram, "77db1120"), externalLocation2.getAddress());
		assertTrue(externalLocation2.getSource() == SourceType.USER_DEFINED);
		DataType dataType2 = externalLocation2.getDataType();
		assertNotNull(dataType2);
		assertTrue(dataType2.isEquivalent(new FloatDataType()));
		externalLocation2 = externalManager.getUniqueExternalLocation("user32.dll", "Brown");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalRemoveConflictUseForAll() throws Exception {

		setupRemoveUseForAll();

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Remove Conflict", MY_BUTTON, true);// Blue removed or changed to Red
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNull(externalLocation);
		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Brown");
		assertNotNull(externalLocation2);
		assertEquals("user32.dll::Brown", externalLocation2.toString());
		assertEquals(addr(resultProgram, "77db1120"), externalLocation2.getAddress());
		assertTrue(externalLocation2.getSource() == SourceType.USER_DEFINED);
		DataType dataType2 = externalLocation2.getDataType();
		assertNotNull(dataType2);
		assertTrue(dataType2.isEquivalent(new FloatDataType()));
		externalLocation2 = externalManager.getUniqueExternalLocation("user32.dll", "Green");
		assertNull(externalLocation);
	}

	private void setupDataTypeUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", null, SourceType.USER_DEFINED);
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Green",
					"77db1120", null, SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());

				setDataTypeForExternalLabel(program, "Modify Latest Program", "user32.dll", "Green",
					"77db1120", new FloatDataType());

				ExternalLocation externalLocation2 =
					externalManager.getUniqueExternalLocation("user32.dll", "Green");
				assertNotNull(externalLocation2);
				assertEquals("user32.dll" + "::" + "Green", externalLocation2.toString());
				Address address2 = externalLocation2.getAddress();
				assertNotNull(address2);
				checkExternalAddress(externalLocation2, "77db1120");
				checkExternalDataType(externalLocation2, new FloatDataType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new ByteDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new ByteDataType());

				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Green",
					"77db1120", new ByteDataType());

				ExternalLocation externalLocation2 =
					externalManager.getUniqueExternalLocation("user32.dll", "Green");
				assertNotNull(externalLocation2);
				assertEquals("user32.dll" + "::" + "Green", externalLocation2.toString());
				Address address2 = externalLocation2.getAddress();
				assertNotNull(address2);
				checkExternalAddress(externalLocation2, "77db1120");
				checkExternalDataType(externalLocation2, new ByteDataType());
			}
		});
	}

	@Test
	public void testExternalDataTypeConflictDontUseForAll() throws Exception {

		setupDataTypeUseForAll();

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Data Type Conflict", LATEST_BUTTON, false);// Float vs Byte data type choose Float
		chooseButtonAndApply("Resolve External Data Type Conflict", MY_BUTTON, false);// Float vs Byte data type choose byte
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Green");
		assertNotNull(externalLocation2);
		checkExternalAddress(externalLocation2, "77db1120");
		checkExternalDataType(externalLocation2, new ByteDataType());
	}

	@Test
	public void testExternalDataTypeConflictUseForAll() throws Exception {

		setupDataTypeUseForAll();

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Data Type Conflict", MY_BUTTON, true);// Float vs Byte data type choose Float
//		chooseButtonAndApply("Resolve External Data Type Conflict", MY_BUTTON, false); // Float vs Byte data type choose byte
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new ByteDataType());

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Green");
		assertNotNull(externalLocation2);
		checkExternalAddress(externalLocation2, "77db1120");
		checkExternalDataType(externalLocation2, new ByteDataType());
	}

	private void setupFunctionVsDataTypeUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Green",
					"77db1120", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Symbol symbol = externalLocation.getSymbol();
					boolean symbolRemoved = symbol.delete();
					assertTrue(symbolRemoved);

					ExternalLocation externalLocation2 =
						externalManager.getUniqueExternalLocation("user32.dll", "Green");
					assertNotNull(externalLocation2);
					Symbol symbol2 = externalLocation2.getSymbol();
					boolean symbolRemoved2 = symbol2.delete();
					assertTrue(symbolRemoved2);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Green",
					"77db1120", new DWordDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);

				ExternalLocation externalLocation2 =
					externalManager.getUniqueExternalLocation("user32.dll", "Green");
				assertNotNull(externalLocation2);
				assertEquals("user32.dll" + "::" + "Green", externalLocation2.toString());
				Address address2 = externalLocation2.getAddress();
				assertNotNull(address2);
				checkExternalAddress(externalLocation2, "77db1120");
				checkExternalDataType(externalLocation2, new DWordDataType());
				Function function2 = externalLocation2.getFunction();
				assertNull(function2);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// add parameters to function.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}

					ExternalLocation externalLocation2 =
						externalManager.getUniqueExternalLocation("user32.dll", "Green");
					assertNotNull(externalLocation2);
					Function function2 = externalLocation2.getFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function2.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function2.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));

				ExternalLocation externalLocation2 =
					externalManager.getUniqueExternalLocation("user32.dll", "Green");
				assertNotNull(externalLocation2);
				assertEquals("user32.dll" + "::" + "Green", externalLocation2.toString());
				Address address2 = externalLocation2.getAddress();
				assertNotNull(address2);
				checkExternalAddress(externalLocation2, "77db1120");
				assertNull(externalLocation2.getDataType());
				Function function2 = externalLocation2.getFunction();
				assertNotNull(function2);
				assertEquals(2, function2.getParameterCount());
				Parameter parameter3 = function2.getParameter(0);
				Parameter parameter4 = function2.getParameter(1);
				assertTrue(parameter3.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter4.getDataType().isEquivalent(new ByteDataType()));
			}
		});
	}

	@Test
	public void testExternalFunctionVsDataTypeDontUseForAll() throws Exception {

		setupFunctionVsDataTypeUseForAll();

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", LATEST_BUTTON,
			false);// Float data type vs Blue(p1, p2)
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", MY_BUTTON,
			false);// DWord data type vs Green(p1, p2)
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());
		Function function = externalLocation.getFunction();
		assertNull(function);

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Green");
		assertNotNull(externalLocation2);
		assertEquals("user32.dll" + "::" + "Green", externalLocation2.toString());
		Address address2 = externalLocation2.getAddress();
		assertNotNull(address2);
		checkExternalAddress(externalLocation2, "77db1120");
		assertNull(externalLocation2.getDataType());
		Function function2 = externalLocation2.getFunction();
		assertNotNull(function2);
		assertEquals(2, function2.getParameterCount());
		Parameter parameter3 = function2.getParameter(0);
		Parameter parameter4 = function2.getParameter(1);
		assertTrue(parameter3.getDataType().isEquivalent(new DWordDataType()));
		assertTrue(parameter4.getDataType().isEquivalent(new ByteDataType()));
	}

	@Test
	public void testExternalFunctionVsDataTypeUseForAll() throws Exception {

		setupFunctionVsDataTypeUseForAll();

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", MY_BUTTON,
			true);// Float data type vs Blue(p1, p2)
//		chooseButtonAndApply("Resolve External Function Versus Data Type Conflict", MY_BUTTON, false); // DWord data type vs Green(p1, p2)
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
		Address address = externalLocation.getAddress();
		assertNotNull(address);
		checkExternalAddress(externalLocation, "77db1020");
		assertNull(externalLocation.getDataType());
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		Parameter parameter2 = function.getParameter(1);
		assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
		assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Green");
		assertNotNull(externalLocation2);
		assertEquals("user32.dll" + "::" + "Green", externalLocation2.toString());
		Address address2 = externalLocation2.getAddress();
		assertNotNull(address2);
		checkExternalAddress(externalLocation2, "77db1120");
		assertNull(externalLocation2.getDataType());
		Function function2 = externalLocation2.getFunction();
		assertNotNull(function2);
		assertEquals(2, function2.getParameterCount());
		Parameter parameter3 = function2.getParameter(0);
		Parameter parameter4 = function2.getParameter(1);
		assertTrue(parameter3.getDataType().isEquivalent(new DWordDataType()));
		assertTrue(parameter4.getDataType().isEquivalent(new ByteDataType()));
	}

	private void setupExternalDetailUseForAll() throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", null, SourceType.USER_DEFINED);
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Oranges",
					"77db1050", null, SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");

				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll",
					"Oranges", "77db1060");

				ExternalLocation externalLocation2 =
					externalManager.getUniqueExternalLocation("user32.dll", "Oranges");
				assertNotNull(externalLocation2);
				assertEquals("user32.dll" + "::" + "Oranges", externalLocation2.toString());
				Address address2 = externalLocation2.getAddress();
				assertNotNull(address2);
				checkExternalAddress(externalLocation2, "77db1060");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1150");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1150");

				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll",
					"Oranges", "77db1080");

				ExternalLocation externalLocation2 =
					externalManager.getUniqueExternalLocation("user32.dll", "Oranges");
				assertNotNull(externalLocation2);
				assertEquals("user32.dll" + "::" + "Oranges", externalLocation2.toString());
				Address address2 = externalLocation2.getAddress();
				assertNotNull(address2);
				checkExternalAddress(externalLocation2, "77db1080");
			}
		});
	}

	@Test
	public void testExternalDetailConflictDontUseForAll() throws Exception {

		setupExternalDetailUseForAll();

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve External Detail Conflict", VariousChoicesPanel.class);
		chooseVariousExternalOptions("user32.dll::Blue", new int[] { INFO_ROW, KEEP_MY }, false);

		checkConflictPanelTitle("Resolve External Detail Conflict", VariousChoicesPanel.class);
		chooseVariousExternalOptions("user32.dll::Oranges", new int[] { INFO_ROW, KEEP_LATEST },
			false);

		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1150");

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Oranges");
		assertNotNull(externalLocation2);
		checkExternalAddress(externalLocation2, "77db1060");
	}

	@Test
	public void testExternalDetailConflictUseForAll() throws Exception {

		setupExternalDetailUseForAll();

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve External Detail Conflict", VariousChoicesPanel.class);
		chooseVariousExternalOptions("user32.dll::Blue", new int[] { INFO_ROW, KEEP_MY }, true);

//		checkConflictPanelTitle("Resolve External Detail Conflict", VariousChoicesPanel.class);
//		chooseVariousExternalOptions("user32.dll::Oranges", new int[] { INFO_ROW, KEEP_MY }, false); // handled by Use For All

		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1150");

		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Oranges");
		assertNotNull(externalLocation2);
		checkExternalAddress(externalLocation2, "77db1080");
	}

	private void setupExternalFunctionRemoveUseForAll(final String[] applesPath,
			final String[] orangesPath) throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function applesFunction = createExternalFunction(program, applesPath,
						addr(program, "77db1234"), new FloatDataType(), SourceType.IMPORTED);
					applesFunction.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new DWordDataType(), 8, program);
					parameter2.setComment("Other Comment");
					applesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setComment("Once upon a time...");
					applesFunction.setNoReturn(true);

					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					parameter1.setComment("Long ago in a land far, far away");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				assertEquals("Once upon a time...", applesFunction.getComment());

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				assertEquals(null, orangesFunction.getComment());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.getSymbol().delete();// Remove the function, but not the external location.

					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.getSymbol().delete();// Remove the function, but not the external location.

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertEquals(false, applesLocation.isFunction());
				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertEquals(false, orangesLocation.isFunction());
			}
		});
	}

	@Test
	public void testExternalFunctionRemoveConflictDontUseForAll() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupExternalFunctionRemoveUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Remove Conflict", LATEST_BUTTON, false);
		chooseButtonAndApply("Resolve External Function Remove Conflict", LATEST_BUTTON, false);
		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals("Once upon a time...", applesFunction.getComment());

		Parameter parameter1 = applesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameter1.getDataType());
		assertEquals("Test Parameter Comment", parameter1.getComment());
		assertEquals("P1", parameter1.getName());
		assertEquals(4, parameter1.getStackOffset());

		Parameter parameter2 = applesFunction.getParameter(1);
		checkDataType(new DWordDataType(), parameter2.getDataType());
		assertEquals("Other Comment", parameter2.getComment());
		assertEquals("P2", parameter2.getName());
		assertEquals(8, parameter2.getStackOffset());

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertEquals(true, orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameterOranges1 = orangesFunction.getParameter(0);
		checkDataType(new ByteDataType(), parameterOranges1.getDataType());
		assertEquals("Long ago in a land far, far away", parameterOranges1.getComment());
		assertEquals("stuff", parameterOranges1.getName());
		assertEquals(4, parameterOranges1.getStackOffset());
	}

	@Test
	public void testExternalFunctionRemoveConflictUseForAll() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupExternalFunctionRemoveUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Function Remove Conflict", MY_BUTTON, true);
//		chooseButtonAndApply("Resolve External Function Remove Conflict", MY_BUTTON, false);
		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertFalse(applesLocation.isFunction());

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertEquals(false, orangesLocation.isFunction());
	}

	private void setupParameterSignatureUseForAll(final String[] applesPath,
			final String[] orangesPath) throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);

					createExternalFunction(program, applesPath, addr(program, "00cc7788"),
						new FloatDataType(), SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(false);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("AX")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setCustomVariableStorage(false);
					Parameter parameterA = new ParameterImpl("type", new WordDataType(), program);
					applesFunction.addParameter(parameterA, SourceType.USER_DEFINED);
					Parameter parameterB =
						new ParameterImpl("index", new IntegerDataType(), program);
					applesFunction.addParameter(parameterB, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("AX")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setCustomVariableStorage(true);
					Parameter parameterA = new ParameterImpl("type", new WordDataType(), program);
					applesFunction.addParameter(parameterA, SourceType.USER_DEFINED);
					Parameter parameterB =
						new ParameterImpl("index", new IntegerDataType(), program);
					applesFunction.addParameter(parameterB, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());

				ExternalLocation applesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
			}
		});
	}

	@Test
	public void testExternalFunctionParameterSignatureConflictDontUseForAll() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupParameterSignatureUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Function Parameters Conflict", MY_BUTTON, false);
		chooseButtonAndApply("Resolve Function Parameters Conflict", LATEST_BUTTON, false);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals(resultProgram.getRegister("AX"), parameter1.getRegister());
		assertFalse(parameter1.isStackVariable());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals(resultProgram.getRegister("BX"), parameter2.getRegister());
		assertFalse(parameter2.isStackVariable());

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertFalse(applesFunction.hasCustomVariableStorage());
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals(null, applesFunction.getComment());

		Parameter parameterA = applesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameterA.getDataType());
		assertEquals("type", parameterA.getName());
		assertEquals(null, parameterA.getRegister());
		assertFalse(parameterA.isRegisterVariable());
		assertFalse(parameterA.isMemoryVariable());
		assertTrue(parameterA.isStackVariable());
		assertEquals(0x4, parameterA.getStackOffset());
		assertFalse(parameterA.isCompoundVariable());
		assertFalse(parameterA.isAutoParameter());
		assertFalse(VariableStorage.UNASSIGNED_STORAGE.equals(parameterA.getVariableStorage()));

		Parameter parameterB = applesFunction.getParameter(1);
		checkDataType(new IntegerDataType(), parameterB.getDataType());
		assertEquals("index", parameterB.getName());
		assertEquals(null, parameterB.getRegister());
		assertFalse(parameterB.isRegisterVariable());
		assertFalse(parameterB.isMemoryVariable());
		assertTrue(parameterB.isStackVariable());
		assertEquals(0x8, parameterB.getStackOffset());
		assertFalse(parameterB.isCompoundVariable());
		assertFalse(parameterB.isAutoParameter());
		assertFalse(VariableStorage.UNASSIGNED_STORAGE.equals(parameterB.getVariableStorage()));
	}

	@Test
	public void testExternalFunctionParameterSignatureConflictUseForAll() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupParameterSignatureUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Function Parameters Conflict", MY_BUTTON, true);
//		chooseButtonAndApply("Resolve Function Parameters Conflict", MY_BUTTON, false); // Handled by Use For All
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals(resultProgram.getRegister("AX"), parameter1.getRegister());
		assertFalse(parameter1.isStackVariable());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals(resultProgram.getRegister("BX"), parameter2.getRegister());
		assertFalse(parameter2.isStackVariable());

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertTrue(applesFunction.hasCustomVariableStorage());
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals(null, applesFunction.getComment());

		Parameter parameterA = applesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameterA.getDataType());
		assertEquals("type", parameterA.getName());
		assertEquals(null, parameterA.getRegister());
		assertFalse(parameterA.isRegisterVariable());
		assertFalse(parameterA.isMemoryVariable());
		assertFalse(parameterA.isStackVariable());
		assertFalse(parameterA.isCompoundVariable());
		assertFalse(parameterA.isAutoParameter());
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, parameterA.getVariableStorage());

		Parameter parameterB = applesFunction.getParameter(1);
		checkDataType(new IntegerDataType(), parameterB.getDataType());
		assertEquals("index", parameterB.getName());
		assertEquals(null, parameterB.getRegister());
		assertFalse(parameterB.isRegisterVariable());
		assertFalse(parameterB.isMemoryVariable());
		assertFalse(parameterB.isStackVariable());
		assertFalse(parameterB.isCompoundVariable());
		assertFalse(parameterB.isAutoParameter());
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, parameterB.getVariableStorage());
	}

	private void setupExternalParameterInfoUseForAll(final String[] applesPath,
			final String[] orangesPath) throws Exception {
		mtf.initialize("WallaceSrc", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function applesFunction = createExternalFunction(program, applesPath,
						addr(program, "77db1234"), new FloatDataType(), SourceType.IMPORTED);
					applesFunction.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new DWordDataType(), 8, program);
					parameter2.setComment("Other Comment");
					applesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					Function orangesFunction = createExternalFunction(program, orangesPath,
						addr(program, "77db1234"), new FloatDataType(), SourceType.IMPORTED);
					orangesFunction.setCustomVariableStorage(true);
					Parameter parameterA = new ParameterImpl("A1", new DWordDataType(), 4, program);
					parameterA.setComment("Test Parameter Comment");
					orangesFunction.addParameter(parameterA, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					Parameter applesParameter1 = applesFunction.getParameter(0);
					applesParameter1.setName("LatestP1", SourceType.USER_DEFINED);
					applesParameter1.setComment("Once upon a time...");

					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter = orangesFunction.getParameter(0);
					parameter.setName("B1", SourceType.USER_DEFINED);
					parameter.setComment("Latest comment.");

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				Parameter applesParameter1 = applesFunction.getParameter(0);
				assertEquals("Once upon a time...", applesParameter1.getComment());

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				Parameter orangesParameter1 = orangesFunction.getParameter(0);
				assertEquals("Latest comment.", orangesParameter1.getComment());
				assertEquals("B1", orangesParameter1.getName());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					Parameter applesParameter1 = applesFunction.getParameter(0);
					applesParameter1.setName("MyP1", SourceType.USER_DEFINED);
					applesParameter1.setComment("This is a sample parameter comment.");

					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter = orangesFunction.getParameter(0);
					parameter.setName("C1", SourceType.USER_DEFINED);
					parameter.setComment("My comment.");

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				Parameter applesParameter1 = applesFunction.getParameter(0);
				assertEquals("This is a sample parameter comment.", applesParameter1.getComment());
				assertEquals("MyP1", applesParameter1.getName());
				Parameter applesParameter2 = applesFunction.getParameter(1);
				assertEquals("Other Comment", applesParameter2.getComment());
				assertEquals("P2", applesParameter2.getName());

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				Parameter orangesParameter1 = orangesFunction.getParameter(0);
				assertEquals("My comment.", orangesParameter1.getComment());
				assertEquals("C1", orangesParameter1.getName());
			}
		});
	}

	@Test
	public void testExternalParameterInfoConflictDontUseForAll() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupExternalParameterInfoUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve Function Parameter Conflict", VariousChoicesPanel.class);
		chooseVariousExternalOptions(null, new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY }, false);

		checkConflictPanelTitle("Resolve Function Parameter Conflict", VariousChoicesPanel.class);
		chooseVariousExternalOptions(null, new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY }, false);

		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals(null, applesFunction.getComment());

		Parameter parameter1 = applesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameter1.getDataType());
		assertEquals("This is a sample parameter comment.", parameter1.getComment());
		assertEquals("LatestP1", parameter1.getName());
		assertEquals(4, parameter1.getStackOffset());

		Parameter parameter2 = applesFunction.getParameter(1);
		checkDataType(new DWordDataType(), parameter2.getDataType());
		assertEquals("P2", parameter2.getName());
		assertEquals("Other Comment", parameter2.getComment());
		assertEquals(8, parameter2.getStackOffset());

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameterA = orangesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameterA.getDataType());
		assertEquals("B1", parameterA.getName());
		assertEquals("My comment.", parameterA.getComment());
		assertEquals(4, parameterA.getStackOffset());
	}

	@Test
	public void testExternalParameterInfoConflictUseForAll() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupExternalParameterInfoUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);

		checkConflictPanelTitle("Resolve Function Parameter Conflict", VariousChoicesPanel.class);
		chooseVariousExternalOptions(null, new int[] { INFO_ROW, KEEP_MY, KEEP_MY }, true);

//		checkConflictPanelTitle("Resolve Function Parameter Conflict", VariousChoicesPanel.class);
//		chooseVariousExternalOptions(null, new int[] { INFO_ROW, KEEP_MY, KEEP_MY }, false); // Handled by Use For All.

		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals(null, applesFunction.getComment());

		Parameter parameter1 = applesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameter1.getDataType());
		assertEquals("This is a sample parameter comment.", parameter1.getComment());
		assertEquals("MyP1", parameter1.getName());
		assertEquals(4, parameter1.getStackOffset());

		Parameter parameter2 = applesFunction.getParameter(1);
		checkDataType(new DWordDataType(), parameter2.getDataType());
		assertEquals("P2", parameter2.getName());
		assertEquals("Other Comment", parameter2.getComment());
		assertEquals(8, parameter2.getStackOffset());

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameterA = orangesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameterA.getDataType());
		assertEquals("C1", parameterA.getName());
		assertEquals("My comment.", parameterA.getComment());
		assertEquals(4, parameterA.getStackOffset());
	}

	private void setupExternalReturnTypeUseForAll(final String[] applesPath,
			final String[] orangesPath) throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function applesFunction = createExternalFunction(program, applesPath,
						addr(program, "77db1020"), new FloatDataType(), SourceType.ANALYSIS);
					assertNotNull(applesFunction);

					Function orangesFunction =
						createExternalFunction(program, orangesPath, addr(program, "77db1270"),
							new PointerDataType(new StringDataType()), SourceType.ANALYSIS);
					assertNotNull(orangesFunction);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setReturnType(new LongDataType(), SourceType.USER_DEFINED);

					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setReturnType(new PointerDataType(new LongDataType()),
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				Function applesFunction = getExternalFunction(program, applesPath);
				assertEquals(0, applesFunction.getParameterCount());
				checkDataType(new LongDataType(), applesFunction.getReturnType());

				Function orangesFunction = getExternalFunction(program, orangesPath);
				assertEquals(0, orangesFunction.getParameterCount());
				checkDataType(new PointerDataType(new LongDataType()),
					orangesFunction.getReturnType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				CategoryPath path = new CategoryPath("/");
				DataType typedefDT = new TypedefDataType(path, "long", new LongDataType(),
					program.getDataTypeManager());
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setReturnType(typedefDT, SourceType.USER_DEFINED);

					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setReturnType(new PointerDataType(new ByteDataType()),
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				Function applesFunction = getExternalFunction(program, applesPath);
				assertEquals(0, applesFunction.getParameterCount());
				checkDataType(typedefDT, applesFunction.getReturnType());

				Function orangesFunction = getExternalFunction(program, orangesPath);
				assertEquals(0, orangesFunction.getParameterCount());
				checkDataType(new PointerDataType(new ByteDataType()),
					orangesFunction.getReturnType());
			}
		});
	}

	@Test
	public void testExternalFunctionReturnTypeDontUseForAll() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupExternalReturnTypeUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, false);
		chooseButtonAndApply("Resolve Function Return Conflict", LATEST_BUTTON, false);
		waitForMergeCompletion();

		Function applesFunction = getExternalFunction(resultProgram, applesPath);
		assertEquals(0, applesFunction.getParameterCount());
		CategoryPath path = new CategoryPath("/");
		DataType typedefDT = new TypedefDataType(path, "long.conflict", new LongDataType(),
			resultProgram.getDataTypeManager());
		checkDataType(typedefDT, applesFunction.getReturnType());

		Function orangesFunction = getExternalFunction(resultProgram, orangesPath);
		assertEquals(0, orangesFunction.getParameterCount());
		checkDataType(new PointerDataType(new LongDataType()), orangesFunction.getReturnType());
	}

	@Test
	public void testExternalFunctionReturnTypeUseForAll() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		setupExternalReturnTypeUseForAll(applesPath, orangesPath);

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, true);
//		chooseButtonAndApply("Resolve Function Return Conflict", MY_BUTTON, false); // Handled by Use For All.
		waitForMergeCompletion();

		Function applesFunction = getExternalFunction(resultProgram, applesPath);
		assertEquals(0, applesFunction.getParameterCount());
		CategoryPath path = new CategoryPath("/");
		DataType typedefDT = new TypedefDataType(path, "long.conflict", new LongDataType(),
			resultProgram.getDataTypeManager());
		checkDataType(typedefDT, applesFunction.getReturnType());

		Function orangesFunction = getExternalFunction(resultProgram, orangesPath);
		assertEquals(0, orangesFunction.getParameterCount());
		checkDataType(new PointerDataType(new ByteDataType()), orangesFunction.getReturnType());
	}

	private void setupVariableStorageConflictUseForAll() throws Exception {
		// 0x010018cf: param_1 is al register (1 param)
		// 0x0100299e: param_1 is eax reg and named fee, param_2 is ah reg, param_3 is tmp register and has comment (3 params)
		// 0x01002c93: param_1 is ecx reg and named parm_1 (3 params)
		// 0x01002cf5: param_2 is cs reg and named parm_3 (5 params)
		// 0x010030e4: param_1 is dh reg (1 param)
		// 0x01004bc0: param_1 is direction reg named parm_1 (1 param)

		mtf.initialize("DiffTestPgm1_X86", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.USER_DEFINED);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func;
					func = getFunction(program, "0x10018cf");
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getFunction(program, "0x100299e");
					func.setCustomVariableStorage(true);
					func.removeParameter(1);

					func = getFunction(program, "0x1002c93");
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 0, 0x4);

					func = getFunction(program, "0x1002cf5");
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 1, 0xc);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func;
					func = getFunction(program, "0x10018cf");
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 0, 0x8);

					func = getFunction(program, "0x100299e");
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 2, 0x8);

					func = getFunction(program, "0x1002c93");
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getFunction(program, "0x1002cf5");
					func.setCustomVariableStorage(true);
					func.removeParameter(1);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	@Test
	public void testExternalVariableStorageConflictDontUseForAll() throws Exception {
		setupVariableStorageConflictUseForAll();

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);// 0x10018cf - signature conflict
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);// 0x100299e - signature conflict

		chooseRadioButton(CHECKED_OUT_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false);// 0x1002c93 - storage conflict
		setUseForAll(false, ScrollingListChoicesPanel.class);
		chooseApply();

		chooseRadioButton(LATEST_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false);// 0x1002cf5 - storage conflict
		setUseForAll(false, ScrollingListChoicesPanel.class);
		chooseApply();

		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register ahReg = context.getRegister("AH");
		Register dhReg = context.getRegister("DH");
		Register dr0Reg = context.getRegister("DR0");
		Register alReg = context.getRegister("AL");

		Function func;
		Parameter[] params;

		func = getFunction(resultProgram, "0x10018cf");
		params = func.getParameters();
		assertEquals(0, params.length);

		func = getFunction(resultProgram, "0x100299e");
		params = func.getParameters();
		assertEquals(3, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertTrue(params[1].isRegisterVariable());
		assertTrue(params[2].isStackVariable());
		assertEquals(alReg, params[0].getRegister());
		assertEquals(ahReg, params[1].getRegister());
		assertEquals(0x8, params[2].getStackOffset());

		func = getFunction(resultProgram, "0x1002c93");
		params = func.getParameters();
		assertEquals(2, params.length);
		assertTrue(params[0].isStackVariable());
		assertTrue(params[1].isStackVariable());
		assertEquals(0x8, params[0].getStackOffset());
		assertEquals(0xc, params[1].getStackOffset());

		func = getFunction(resultProgram, "0x1002cf5");
		params = func.getParameters();
		assertEquals(5, params.length);
		assertTrue(params[0].isStackVariable());
		assertTrue(params[1].isStackVariable());
		assertTrue(params[2].isStackVariable());
		assertTrue(params[3].isStackVariable());
		assertTrue(params[4].isStackVariable());
		assertEquals(0x8, params[0].getStackOffset());
		assertEquals(0xc, params[1].getStackOffset());
		assertEquals(0x10, params[2].getStackOffset());
		assertEquals(0x14, params[3].getStackOffset());
		assertEquals(0x18, params[4].getStackOffset());

		func = getFunction(resultProgram, "0x10030e4");
		params = func.getParameters();
		assertEquals(1, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertEquals(dhReg, params[0].getRegister());

		func = getFunction(resultProgram, "0x1004bc0");
		params = func.getParameters();
		assertEquals(1, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertEquals(dr0Reg, params[0].getRegister());
	}

	@Test
	public void testExternalVariableStorageConflictUseForAll() throws Exception {
		setupVariableStorageConflictUseForAll();

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);// 0x10018cf - signature conflict
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);// 0x100299e - signature conflict

		chooseRadioButton(CHECKED_OUT_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false);// 0x1002c93 - storage conflict
		setUseForAll(true, ScrollingListChoicesPanel.class);
		chooseApply();

//		chooseRadioButton(CHECKED_OUT_LIST_BUTTON_NAME, ScrollingListChoicesPanel.class, false); // 0x1002cf5 - storage conflict
//		setUseForAll(false, ScrollingListChoicesPanel.class);
//		chooseApply(); // Handled by Use For All.

		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register ahReg = context.getRegister("AH");
		Register dhReg = context.getRegister("DH");
		Register dr0Reg = context.getRegister("DR0");
		Register alReg = context.getRegister("AL");

		Function func;
		Parameter[] params;

		func = getFunction(resultProgram, "0x10018cf");
		params = func.getParameters();
		assertEquals(0, params.length);

		func = getFunction(resultProgram, "0x100299e");
		params = func.getParameters();
		assertEquals(3, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertTrue(params[1].isRegisterVariable());
		assertTrue(params[2].isStackVariable());
		assertEquals(alReg, params[0].getRegister());
		assertEquals(ahReg, params[1].getRegister());
		assertEquals(0x8, params[2].getStackOffset());

		func = getFunction(resultProgram, "0x1002c93");
		params = func.getParameters();
		assertEquals(2, params.length);
		assertTrue(params[0].isStackVariable());
		assertTrue(params[1].isStackVariable());
		assertEquals(0x8, params[0].getStackOffset());
		assertEquals(0xc, params[1].getStackOffset());

		func = getFunction(resultProgram, "0x1002cf5");
		params = func.getParameters();
		assertEquals(4, params.length);
		assertTrue(params[0].isStackVariable());
		assertTrue(params[1].isStackVariable());
		assertTrue(params[2].isStackVariable());
		assertTrue(params[3].isStackVariable());
		assertEquals(0x8, params[0].getStackOffset());
		assertEquals(0x10, params[1].getStackOffset());
		assertEquals(0x14, params[2].getStackOffset());
		assertEquals(0x18, params[3].getStackOffset());

		func = getFunction(resultProgram, "0x10030e4");
		params = func.getParameters();
		assertEquals(1, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertEquals(dhReg, params[0].getRegister());

		func = getFunction(resultProgram, "0x1004bc0");
		params = func.getParameters();
		assertEquals(1, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertEquals(dr0Reg, params[0].getRegister());
	}

	// =========================

	@Override
	ExternalLocation createExternalLabel(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString, DataType dataType,
			SourceType sourceType) {
		Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Library externalLibrary;
			Symbol librarySymbol =
				symbolTable.getSymbol(library, Address.NO_ADDRESS, program.getGlobalNamespace());
			if (librarySymbol != null && librarySymbol.getSymbolType() == SymbolType.LIBRARY) {
				externalLibrary = (Library) librarySymbol.getObject();
			}
			else {
				externalLibrary = symbolTable.createExternalLibrary(library, sourceType);
			}
			ExternalLocation externalLocation =
				externalManager.addExtLocation(externalLibrary, label, address, sourceType);
			assertNotNull(externalLocation);
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
	 * @param addressAsString
	 * @param sourceType
	 * @return
	 */
	@Override
	ExternalLocation createExternalFunction(ProgramDB program, String transactionDescription,
			String library, String label, String addressAsString, SourceType sourceType) {
		Address address = (addressAsString != null) ? addr(program, addressAsString) : null;
		int txId = program.startTransaction(transactionDescription);
		boolean commit = false;
		ExternalManager externalManager = program.getExternalManager();
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Library externalLibrary;
			Symbol librarySymbol =
				symbolTable.getSymbol(library, Address.NO_ADDRESS, program.getGlobalNamespace());
			if (librarySymbol != null && librarySymbol.getSymbolType() == SymbolType.LIBRARY) {
				externalLibrary = (Library) librarySymbol.getObject();
			}
			else {
				externalLibrary = symbolTable.createExternalLibrary(library, sourceType);
			}
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

	void createExternalLabel(MergeProgram mergeProgram, String[] path, String memoryAddress,
			DataType dt, SourceType sourceType) {

		int nameIndex = path.length - 1;
		Library currentLibrary = null;
		for (int i = 0; i < nameIndex; i++) {
			currentLibrary = mergeProgram.createExternalLibrary(path[i], sourceType);
		}

		mergeProgram.addExternalLocation(currentLibrary, path[nameIndex], memoryAddress, dt,
			sourceType);
	}

	protected void chooseVariousExternalOptions(final String externalLabelPathName,
			final int[] options, boolean useForAll) throws Exception {
		waitForPrompting();
		Window window = windowForComponent(getMergePanel());
		ExternalConflictInfoPanel externalInfoComp =
			findComponent(window, ExternalConflictInfoPanel.class);
		assertNotNull(externalInfoComp);
		assertEquals(externalLabelPathName, externalInfoComp.getLabelPathName());
		VariousChoicesPanel choiceComp = findComponent(window, VariousChoicesPanel.class);
		assertNotNull(choiceComp);
		for (int row = 0; row < options.length; row++) {
			if (options[row] == CANCELED) {
				try {
					pressButtonByText(window, "Cancel", false);
					return;
				}
				catch (AssertionError e) {
					Assert.fail(e.getMessage());
				}
			}
			else if (options[row] == INFO_ROW) {
				continue;
			}
			String compName = choiceComp.getComponentName(row, optionToColumn(options[row]));
			Component comp = findComponentByName(choiceComp, compName, false);
			if (comp instanceof AbstractButton) {
				((AbstractButton) comp).setSelected(true);
			}
			else if (comp instanceof JCheckBox) {
				((JCheckBox) comp).setSelected(true);
			}
		}

		waitForPostedSwingRunnables();
		setUseForAll(useForAll, VariousChoicesPanel.class);

		try {
			waitForApply(true);
			pressButtonByText(window, "Apply");
			waitForPostedSwingRunnables();
			waitForApply(false);
		}
		catch (UsrException e) {
			Assert.fail(e.getMessage());
		}
	}

	/**
	 * @param option
	 * @return
	 */
	private int optionToColumn(int option) {
		switch (option) {
			case KEEP_LATEST:
				return 1;
			case KEEP_MY:
				return 2;
			case KEEP_ORIGINAL:
				return 3;
		}
		return -1;
	}
}
