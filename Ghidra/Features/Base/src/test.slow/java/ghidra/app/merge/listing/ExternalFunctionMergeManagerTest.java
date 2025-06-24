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

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.cmd.function.AddRegisterParameterCommand;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the merge of external function variables.
 */
public class ExternalFunctionMergeManagerTest extends AbstractExternalMergerTest {

	public ExternalFunctionMergeManagerTest() {
		super();
	}

	@Test
	public void testChangeLatestFunction() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addStackParameter(applesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(applesFunction, "P2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// No Changes
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		Function function =
			getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(function);
		assertEquals("FRED", function.getName());
		assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
		checkDataType(new FloatDataType(), function.getReturnType());
		assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
		assertEquals("unknown", function.getCallingConventionName());
		assertEquals(new AddressSet(), function.getBody());
		assertEquals(null, function.getComment());
		assertEquals(null, function.getRepeatableComment());
		assertEquals(true, function.hasCustomVariableStorage());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(true, function.hasVarArgs());
		assertEquals(true, function.isExternal());
		assertEquals(false, function.isInline());
		assertEquals(false, function.isThunk());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(3, function.getParameterCount());

		Parameter parameter1 = function.getParameter(0);
		assertEquals("Amount", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());
		assertEquals("New Parameter1 Comment", parameter1.getComment());
//		assertEquals(SourceType.ANALYSIS, parameter1.getSource());
		assertEquals(4, parameter1.getLength());
		assertEquals(4, parameter1.getStackOffset());
		assertEquals(null, parameter1.getRegister());

		Parameter parameter2 = function.getParameter(1);
		assertEquals("Value", parameter2.getName());
		checkDataType(new ByteDataType(), parameter2.getDataType());
		assertEquals("New P2 Comment", parameter2.getComment());
//		assertEquals(SourceType.IMPORTED, parameter2.getSource());
		assertEquals(1, parameter2.getLength());
		assertEquals(8, parameter2.getStackOffset());
		assertEquals(null, parameter2.getRegister());

		Parameter parameter3 = function.getParameter(2);
		assertEquals("P3", parameter3.getName());
		checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
		assertEquals("Test Parameter3 Comment", parameter3.getComment());
//		assertEquals(SourceType.IMPORTED, parameter3.getSource());
		assertEquals(4, parameter3.getLength());
		assertEquals(12, parameter3.getStackOffset());
		assertEquals(null, parameter3.getRegister());
	}

	@Test
	public void testChangeMyFunction() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addStackParameter(applesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(applesFunction, "P2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				// No Changes
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		Function function =
			getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(function);
		assertEquals("FRED", function.getName());
		assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
		checkDataType(new FloatDataType(), function.getReturnType());
		assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
		assertEquals("unknown", function.getCallingConventionName());
		assertEquals(new AddressSet(), function.getBody());
		assertEquals(null, function.getComment());
		assertEquals(null, function.getRepeatableComment());
		assertEquals(true, function.hasCustomVariableStorage());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(true, function.hasVarArgs());
		assertEquals(true, function.isExternal());
		assertEquals(false, function.isInline());
		assertEquals(false, function.isThunk());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(3, function.getParameterCount());

		Parameter parameter1 = function.getParameter(0);
		assertEquals("Amount", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());
		assertEquals("New Parameter1 Comment", parameter1.getComment());
//		assertEquals(SourceType.ANALYSIS, parameter1.getSource());
		assertEquals(4, parameter1.getLength());
		assertEquals(4, parameter1.getStackOffset());
		assertEquals(null, parameter1.getRegister());

		Parameter parameter2 = function.getParameter(1);
		assertEquals("Value", parameter2.getName());
		checkDataType(new ByteDataType(), parameter2.getDataType());
		assertEquals("New P2 Comment", parameter2.getComment());
//		assertEquals(SourceType.IMPORTED, parameter2.getSource());
		assertEquals(1, parameter2.getLength());
		assertEquals(8, parameter2.getStackOffset());
		assertEquals(null, parameter2.getRegister());

		Parameter parameter3 = function.getParameter(2);
		assertEquals("P3", parameter3.getName());
		checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
		assertEquals("Test Parameter3 Comment", parameter3.getComment());
//		assertEquals(SourceType.IMPORTED, parameter3.getSource());
		assertEquals(4, parameter3.getLength());
		assertEquals(12, parameter3.getStackOffset());
		assertEquals(null, parameter3.getRegister());
	}

	@Test
	public void testChangeLatestFunctionRemoveMyFunctionPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addStackParameter(applesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(applesFunction, "P2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function externalFunction =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					externalFunction.getSymbol().delete();
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		Function function =
			getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(function);
		assertEquals("FRED", function.getName());
		assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
		checkDataType(new FloatDataType(), function.getReturnType());
		assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
		assertEquals("unknown", function.getCallingConventionName());
		assertEquals(new AddressSet(), function.getBody());
		assertEquals(null, function.getComment());
		assertEquals(null, function.getRepeatableComment());
		assertEquals(true, function.hasCustomVariableStorage());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(true, function.hasVarArgs());
		assertEquals(true, function.isExternal());
		assertEquals(false, function.isInline());
		assertEquals(false, function.isThunk());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(3, function.getParameterCount());

		Parameter parameter1 = function.getParameter(0);
		assertEquals("Amount", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());
		assertEquals("New Parameter1 Comment", parameter1.getComment());
//		assertEquals(SourceType.ANALYSIS, parameter1.getSource());
		assertEquals(4, parameter1.getLength());
		assertEquals(4, parameter1.getStackOffset());
		assertEquals(null, parameter1.getRegister());

		Parameter parameter2 = function.getParameter(1);
		assertEquals("Value", parameter2.getName());
		checkDataType(new ByteDataType(), parameter2.getDataType());
		assertEquals("New P2 Comment", parameter2.getComment());
//		assertEquals(SourceType.IMPORTED, parameter2.getSource());
		assertEquals(1, parameter2.getLength());
		assertEquals(8, parameter2.getStackOffset());
		assertEquals(null, parameter2.getRegister());

		Parameter parameter3 = function.getParameter(2);
		assertEquals("P3", parameter3.getName());
		checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
		assertEquals("Test Parameter3 Comment", parameter3.getComment());
//		assertEquals(SourceType.IMPORTED, parameter3.getSource());
		assertEquals(4, parameter3.getLength());
		assertEquals(12, parameter3.getStackOffset());
		assertEquals(null, parameter3.getRegister());
	}

	@Test
	public void testChangeLatestFunctionRemoveMyFunctionPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addStackParameter(applesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(applesFunction, "P2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function externalFunction =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					externalFunction.getSymbol().delete();
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		ExternalLocation location =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(location);
	}

	@Test
	public void testRemoveLatestFunctionChangeMyFunctionPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addStackParameter(applesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(applesFunction, "P2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function externalFunction =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					externalFunction.getSymbol().delete();
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		ExternalLocation location =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(location);
	}

	@Test
	public void testRemoveLatestFunctionChangeMyFunctionPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addStackParameter(applesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(applesFunction, "P2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function externalFunction =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					externalFunction.getSymbol().delete();
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		Function function =
			getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(function);
		assertEquals("FRED", function.getName());
		assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
		checkDataType(new FloatDataType(), function.getReturnType());
		assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
		assertEquals("unknown", function.getCallingConventionName());
		assertEquals(new AddressSet(), function.getBody());
		assertEquals(null, function.getComment());
		assertEquals(null, function.getRepeatableComment());
		assertEquals(true, function.hasCustomVariableStorage());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(true, function.hasVarArgs());
		assertEquals(true, function.isExternal());
		assertEquals(false, function.isInline());
		assertEquals(false, function.isThunk());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(3, function.getParameterCount());

		Parameter parameter1 = function.getParameter(0);
		assertEquals("Amount", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());
		assertEquals("New Parameter1 Comment", parameter1.getComment());
//		assertEquals(SourceType.ANALYSIS, parameter1.getSource());
		assertEquals(4, parameter1.getLength());
		assertEquals(4, parameter1.getStackOffset());
		assertEquals(null, parameter1.getRegister());

		Parameter parameter2 = function.getParameter(1);
		assertEquals("Value", parameter2.getName());
		checkDataType(new ByteDataType(), parameter2.getDataType());
		assertEquals("New P2 Comment", parameter2.getComment());
//		assertEquals(SourceType.IMPORTED, parameter2.getSource());
		assertEquals(1, parameter2.getLength());
		assertEquals(8, parameter2.getStackOffset());
		assertEquals(null, parameter2.getRegister());

		Parameter parameter3 = function.getParameter(2);
		assertEquals("P3", parameter3.getName());
		checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
		assertEquals("Test Parameter3 Comment", parameter3.getComment());
//		assertEquals(SourceType.IMPORTED, parameter3.getSource());
		assertEquals(4, parameter3.getLength());
		assertEquals(12, parameter3.getStackOffset());
		assertEquals(null, parameter3.getRegister());
	}

	@Test
	public void testChangeMyFunctionWhenAddressConflictKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addParameter(applesFunction, "P1", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");
					addParameter(applesFunction, "P2", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just created.
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertEquals("apples", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(DataType.DEFAULT, function.getReturnType());
				assertEquals(SourceType.DEFAULT, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(false, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(false, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(2, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("P1", parameter1.getName());
				checkDataType(new DWordDataType(), parameter1.getDataType());
				assertEquals("Test Parameter Comment", parameter1.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("P2", parameter2.getName());
				checkDataType(new DWordDataType(), parameter2.getDataType());
				assertEquals("Test Parameter Comment", parameter2.getComment());
				assertEquals(SourceType.USER_DEFINED, parameter2.getSource());
				assertEquals(4, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					// Set the external Mem Address
					ExternalLocation externalLocation =
						getExternalLocation(program, new String[] { "user32.dll", "apples" });

					try {
						externalLocation.setLocation(externalLocation.getLabel(),
							addr(program, "70db1234"), externalLocation.getSource());
					}
					catch (DuplicateNameException e) {
						Assert.fail();
					}
					catch (InvalidInputException e) {
						Assert.fail();
					}
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					// Set the external Mem Address
					ExternalLocation externalLocation =
						getExternalLocation(program, new String[] { "user32.dll", "apples" });

					try {
						externalLocation.setLocation(externalLocation.getLabel(),
							addr(program, "77cc4444"), externalLocation.getSource());
					}
					catch (DuplicateNameException e) {
						Assert.fail();
					}
					catch (InvalidInputException e) {
						Assert.fail();
					}

					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("FRED", SourceType.USER_DEFINED);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
//					function.setCallingConvention();
//					function.setBody();
//					function.setComment();
					function.setCustomVariableStorage(true);
//					function.setRepeatableComment();
//					function.setSignatureSource();
					function.setVarArgs(true);

					Parameter parameter1 = function.getParameter(0);
					parameter1.setComment("New Parameter1 Comment");
					parameter1.setName("Amount", SourceType.ANALYSIS);
					parameter1.setDataType(new FloatDataType(), SourceType.IMPORTED);

					Parameter parameter2 = function.getParameter(1);
					parameter2.setComment("New P2 Comment");
					parameter2.setDataType(new ByteDataType(), SourceType.ANALYSIS);
					parameter2.setName("Value", SourceType.IMPORTED);

					addStackParameter(function, "P3", SourceType.IMPORTED,
						new PointerDataType(new CharDataType()), 12, "Test Parameter3 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				// Check the function just changed.
				Function applesFunction =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				assertNull(applesFunction);
				Function function =
					getExternalFunction(program, new String[] { "user32.dll", "FRED" });
				assertEquals("FRED", function.getName());
				assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
				checkDataType(new FloatDataType(), function.getReturnType());
				assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
				assertEquals("unknown", function.getCallingConventionName());
				assertEquals(new AddressSet(), function.getBody());
				assertEquals(null, function.getComment());
				assertEquals(null, function.getRepeatableComment());
				assertEquals(true, function.hasCustomVariableStorage());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(true, function.hasVarArgs());
				assertEquals(true, function.isExternal());
				assertEquals(false, function.isInline());
				assertEquals(false, function.isThunk());
				assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
				assertEquals(3, function.getParameterCount());

				Parameter parameter1 = function.getParameter(0);
				assertEquals("Amount", parameter1.getName());
				checkDataType(new FloatDataType(), parameter1.getDataType());
				assertEquals("New Parameter1 Comment", parameter1.getComment());
				assertEquals(SourceType.ANALYSIS, parameter1.getSource());
				assertEquals(4, parameter1.getLength());
				assertEquals(4, parameter1.getStackOffset());
				assertEquals(null, parameter1.getRegister());

				Parameter parameter2 = function.getParameter(1);
				assertEquals("Value", parameter2.getName());
				checkDataType(new ByteDataType(), parameter2.getDataType());
				assertEquals("New P2 Comment", parameter2.getComment());
				assertEquals(SourceType.IMPORTED, parameter2.getSource());
				assertEquals(1, parameter2.getLength());
				assertEquals(8, parameter2.getStackOffset());
				assertEquals(null, parameter2.getRegister());

				Parameter parameter3 = function.getParameter(2);
				assertEquals("P3", parameter3.getName());
				checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
				assertEquals("Test Parameter3 Comment", parameter3.getComment());
				assertEquals(SourceType.IMPORTED, parameter3.getSource());
				assertEquals(4, parameter3.getLength());
				assertEquals(12, parameter3.getStackOffset());
				assertEquals(null, parameter3.getRegister());
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });// Memory Address conflict
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		ExternalLocation externalLocation =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(externalLocation);
		assertEquals("70db1234", externalLocation.getAddress().toString());

		Function function =
			getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" });
		assertNotNull(function);
		assertEquals("FRED", function.getName());
		assertEquals(SourceType.USER_DEFINED, function.getSymbol().getSource());
		checkDataType(new FloatDataType(), function.getReturnType());
		assertEquals(SourceType.USER_DEFINED, function.getReturn().getSource());
		assertEquals("unknown", function.getCallingConventionName());
		assertEquals(new AddressSet(), function.getBody());
		assertEquals(null, function.getComment());
		assertEquals(null, function.getRepeatableComment());
		assertEquals(true, function.hasCustomVariableStorage());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(true, function.hasVarArgs());
		assertEquals(true, function.isExternal());
		assertEquals(false, function.isInline());
		assertEquals(false, function.isThunk());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals(3, function.getParameterCount());

		Parameter parameter1 = function.getParameter(0);
		assertEquals("Amount", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());
		assertEquals("New Parameter1 Comment", parameter1.getComment());
//		assertEquals(SourceType.ANALYSIS, parameter1.getSource());
		assertEquals(4, parameter1.getLength());
		assertEquals(4, parameter1.getStackOffset());
		assertEquals(null, parameter1.getRegister());

		Parameter parameter2 = function.getParameter(1);
		assertEquals("Value", parameter2.getName());
		checkDataType(new ByteDataType(), parameter2.getDataType());
		assertEquals("New P2 Comment", parameter2.getComment());
//		assertEquals(SourceType.IMPORTED, parameter2.getSource());
		assertEquals(1, parameter2.getLength());
		assertEquals(8, parameter2.getStackOffset());
		assertEquals(null, parameter2.getRegister());

		Parameter parameter3 = function.getParameter(2);
		assertEquals("P3", parameter3.getName());
		checkDataType(new PointerDataType(new CharDataType()), parameter3.getDataType());
		assertEquals("Test Parameter3 Comment", parameter3.getComment());
//		assertEquals(SourceType.IMPORTED, parameter3.getSource());
		assertEquals(4, parameter3.getLength());
		assertEquals(12, parameter3.getStackOffset());
		assertEquals(null, parameter3.getRegister());
	}

	@Test
	public void testChangeFunctionNameNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addParameter(applesFunction, "P1", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });

					function.setName("BARNEY", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				assertNotNull(
					getExternalFunction(program, new String[] { "user32.dll", "BARNEY" }));
				assertNull(getExternalFunction(program, new String[] { "user32.dll", "apples" }));
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function function =
						getExternalFunction(program, new String[] { "user32.dll", "oranges" });

					function.setName("FRED", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				assertNotNull(getExternalFunction(program, new String[] { "user32.dll", "FRED" }));
				assertNull(getExternalFunction(program, new String[] { "user32.dll", "oranges" }));
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" }));
		assertNotNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "BARNEY" }));
		assertNotNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" }));
	}

	@Test
	public void testChangeFunctionNameWithConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" });
					addParameter(applesFunction, "P1", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "P1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setName("BARNEY", SourceType.USER_DEFINED);
					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setName("BETTY", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setName("FRED", SourceType.USER_DEFINED);
					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setName("WILMA", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		checkExternalPanelInfo(MY_TITLE, "user32.dll::FRED", 1, 2);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		checkExternalPanelInfo(MY_TITLE, "user32.dll::WILMA", 2, 2);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" }));
		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" }));
		assertNotNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "BARNEY" }));
		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "BETTY" }));
		assertNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "FRED" }));
		assertNotNull(getExternalFunction(resultProgram, new String[] { "user32.dll", "WILMA" }));
	}

	@Test
	public void testAddExternalFunctionsWithAddressConflict() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					createExternalFunction(program, new String[] { "user32.dll", "BETTY" },
						addr(program, "1002239"), null, SourceType.USER_DEFINED);
					createExternalFunction(program, new String[] { "user32.dll", "BARNEY" },
						addr(program, "77db1020"), null, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					createExternalFunction(program, new String[] { "user32.dll", "BETTY" },
						addr(program, "10063b4"));
					createExternalFunction(program, new String[] { "user32.dll", "BARNEY" },
						addr(program, "77db1130"));
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);

		chooseButtonAndApply("Resolve External Add Conflict",
			ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME);

		chooseButtonAndApply("Resolve External Add Conflict",
			ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME);

		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		List<ExternalLocation> externalLocations =
			externalManager.getExternalLocations("user32.dll", "BETTY");
		assertEquals(2, externalLocations.size());
		assertHasDifferentAddresses(externalLocations, "1002239", "10063b4");

		List<ExternalLocation> externalLocations2 =
			externalManager.getExternalLocations("user32.dll", "BARNEY");
		assertEquals(2, externalLocations2.size());
		assertHasDifferentAddresses(externalLocations2, "77db1020", "77db1130");

	}

	private void assertHasDifferentAddresses(List<ExternalLocation> externalLocations,
			String addrString1, String addrString2) {
		Address addr1 = addr(resultProgram, addrString1);
		Address addr2 = addr(resultProgram, addrString2);

		Address extAddr1 = externalLocations.get(0).getAddress();
		Address extAddr2 = externalLocations.get(1).getAddress();
		if (addr1.equals(extAddr1) && addr2.equals(extAddr2)) {
			return;
		}
		if (addr1.equals(extAddr2) && addr2.equals(extAddr1)) {
			return;
		}
		fail("Expected addresses: " + addr1 + ", " + addr2 + " but got " + extAddr1 + ", " +
			extAddr2);
	}

	@Test
	public void testAddExternalFunctionsWithFunctionConflicts() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					createExternalFunction(program, new String[] { "user32.dll", "BETTY" },
						addr(program, "1002239"));

					createExternalFunction(program, new String[] { "user32.dll", "BARNEY" },
						addr(program, "77db1020"));
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					createExternalFunction(program, new String[] { "user32.dll", "BETTY" },
						addr(program, "77db1020"));

					createExternalFunction(program, new String[] { "user32.dll", "BARNEY" },
						addr(program, "1002239"));
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON); // BETTY has address conflict
		chooseButtonAndApply("Resolve External Add Conflict", KEEP_BOTH_BUTTON); // BARNEY has address conflict

		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		List<ExternalLocation> externalLocations =
			externalManager.getExternalLocations("user32.dll", "BARNEY");
		assertEquals(2, externalLocations.size());
		assertHasDifferentAddresses(externalLocations, "1002239", "77db1020");

		externalLocations = externalManager.getExternalLocations("user32.dll", "BETTY");
		assertEquals(1, externalLocations.size());
		assertEquals("01002239", externalLocations.get(0).getAddress().toString());

	}

	@Test
	public void testRemoveVsChangeParamConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function function =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.getParameter(0).setComment("New my comment.");
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		assertEquals(0, func.getParameterCount());
		assertSameDataType(new ByteDataType(), func.getReturnType());
	}

	@Test
	public void testRemoveVsChangeParamConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function function =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.getParameter(0).setComment("New my comment.");
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		assertEquals(1, func.getParameterCount());
		Parameter parameter = func.getParameter(0);
		assertSameDataType(new DWordDataType(), parameter.getDataType());
		assertEquals("P1", parameter.getName());
		assertEquals("New my comment.", parameter.getComment());
		assertSameDataType(new ByteDataType(), func.getReturnType());
	}

	@Test
	public void testRemoveVsRenameParamConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function function =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.getParameter(0).setName("NewMyName", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		assertEquals(0, func.getParameterCount());

	}

	@Test
	public void testRemoveVsRenameParamConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function function =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.getParameter(0).setName("NewMyName", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter parm = func.getParameter(0);
		assertEquals("NewMyName", parm.getName());
	}

	@Test
	public void testChangeToStackParamConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new FloatDataType(), program);
					applesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
					addParameter(orangesFunction, "A2", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					assertNotNull(func);
					Parameter parameter0 = func.getParameter(0);
					assertNotNull(parameter0);
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					Parameter parameter1 = func.getParameter(1);
					parameter1.setName("NewLatestName", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					assertNotNull(func);
					Parameter parameter0 = func.getParameter(0);
					assertNotNull(parameter0);
					parameter0.setName("NewMyName", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					Parameter parameter1 = func.getParameter(1);
					assertNotNull(parameter1);
					func.removeParameter(1);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);// byte apples(dword NewMyName, float P2)
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);// undefined oranges(dword A1)
		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register r12Reg = context.getRegister("r12");
		Register r11Reg = context.getRegister("r11");

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("NewMyName", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("P2", parameters[1].getName());
		assertEquals(r11Reg, parameters[1].getRegister());
		assertTrue(new FloatDataType().isEquivalent(parameters[1].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	@Test
	public void testAddRegParamVsChangeConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addStackParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(orangesFunction, "A2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					Parameter param0;
					AddRegisterParameterCommand cmd;
					Register regR5 = program.getProgramContext().getRegister("r5");

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					cmd = new AddRegisterParameterCommand(func, regR5, null,
						new Undefined4DataType(), 1, SourceType.USER_DEFINED);
					cmd.applyTo(program);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					param0 = func.getParameter(0);
					assertNotNull(param0);
					param0.setName("NewParamName2", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					Parameter param0;
					AddRegisterParameterCommand cmd;
					Register regR6 = program.getProgramContext().getRegister("r6");

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					param0 = func.getParameter(0);
					assertNotNull(param0);
					param0.setName("NewParamName1", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					cmd = new AddRegisterParameterCommand(func, regR6, null,
						new Undefined4DataType(), 1, SourceType.USER_DEFINED);
					cmd.applyTo(program);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register r12Reg = context.getRegister("r12");
		Register r11Reg = context.getRegister("r11");
		Register r6Reg = context.getRegister("r6");

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("NewParamName1", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(3, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("param_2", parameters[1].getName());
		assertEquals(r6Reg, parameters[1].getRegister());
		assertTrue(new Undefined4DataType().isEquivalent(parameters[1].getDataType()));
		assertEquals("A2", parameters[2].getName());
		assertEquals(r11Reg, parameters[2].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[2].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	@Test
	public void testAddDiffRegParamsConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					assertNotNull(orangesFunction);
					parameter1 = new ParameterImpl("A1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					AddRegisterParameterCommand cmd;
					Register regR1 = program.getProgramContext().getRegister("r1");
					Register regR3 = program.getProgramContext().getRegister("r3");

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					cmd = new AddRegisterParameterCommand(func, regR1, "Latest_1",
						new FloatDataType(), 1, SourceType.USER_DEFINED);
					cmd.applyTo(program);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					cmd = new AddRegisterParameterCommand(func, regR3, "Latest_3",
						new FloatDataType(), 1, SourceType.USER_DEFINED);
					cmd.applyTo(program);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					AddRegisterParameterCommand cmd;
					Register regR4 = program.getProgramContext().getRegister("r4");
					Register regR6 = program.getProgramContext().getRegister("r6");

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					cmd = new AddRegisterParameterCommand(func, regR4, "My_4",
						new Undefined4DataType(), 1, SourceType.USER_DEFINED);
					cmd.applyTo(program);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					cmd = new AddRegisterParameterCommand(func, regR6, "My_6",
						new Undefined4DataType(), 1, SourceType.USER_DEFINED);
					cmd.applyTo(program);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register r12Reg = context.getRegister("r12");
		Register r4Reg = context.getRegister("r4");
		Register r3Reg = context.getRegister("r3");

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("P1", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("My_4", parameters[1].getName());
		assertEquals(r4Reg, parameters[1].getRegister());
		assertTrue(new Undefined4DataType().isEquivalent(parameters[1].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("Latest_3", parameters[1].getName());
		assertEquals(r3Reg, parameters[1].getRegister());
		assertTrue(new FloatDataType().isEquivalent(parameters[1].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	@Test
	public void testRemoveRegParamNoConflict() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
					addParameter(orangesFunction, "A2", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");

					Function pearsFunction =
						createExternalFunction(program, new String[] { "user32.dll", "pears" });
					addParameter(pearsFunction, "B1", SourceType.USER_DEFINED, new DWordDataType(),
						"Test B1");
					addParameter(pearsFunction, "B2", SourceType.USER_DEFINED, new DWordDataType(),
						"Test B2");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.removeParameter(1);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "pears" });
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register r12Reg = context.getRegister("r12");

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(0, parameters.length);
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "pears" });
		parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("B2", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	/**
	 * Remove a register parameter vs change the register on a register parameter.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsChangeRegParam() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test A1 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ProgramContext context = program.getProgramContext();
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					changeToRegisterParameter(func, 0, context.getRegister("r2"));
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ProgramContext context = program.getProgramContext();
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					changeToRegisterParameter(func, 0, context.getRegister("r3"));

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register r3Reg = context.getRegister("r3");

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("P1", parameters[0].getName());
		assertEquals(r3Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(0, parameters.length);
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	/**
	 * Remove a register parameter vs change an attribute (name, dt, comment) of a register
	 * parameter.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsChangeRegParamName() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test A1 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.getParameter(0).setName("X1", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.getParameter(0).setName("Y1", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("Y1", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(0, parameters.length);
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	/**
	 * Remove a register parameter vs change an attribute (name, dt, comment) of a register
	 * parameter.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsChangeRegParamDataType() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test A1 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.getParameter(0).setDataType(new FloatDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.getParameter(0).setDataType(new FloatDataType(), SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("P1", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new FloatDataType().isEquivalent(parameters[0].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(0, parameters.length);
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	/**
	 * Remove a register parameter vs change an attribute (name, dt, comment) of a register
	 * parameter.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsChangeRegParamComment() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test A1 Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.getParameter(0).setComment("LATEST Comment");
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.getParameter(0).setComment("MY Comment");

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("P1", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("MY Comment", parameters[0].getComment());
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(0, parameters.length);
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	/**
	 * Remove a register parameter vs change the register on a register parameter.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsChangeRegParamToStack() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					assertNotNull(orangesFunction);
					parameter1 = new ParameterImpl("A1", new DWordDataType(), program);
					parameter1.setComment("Test A1 Comment");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 0, 0x8);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;
					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					func.removeParameter(0);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 0, 0x8);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(0, parameters.length);
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals(8, parameters[0].getStackOffset());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	@Test
	public void testChangeRegParamNoConflict() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					orangesFunction.setCustomVariableStorage(true);
					addStackParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), 4, "Test Parameter Comment");
					addStackParameter(orangesFunction, "A2", SourceType.USER_DEFINED,
						new DWordDataType(), 8, "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func;

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					Parameter[] parameters = func.getParameters();
					parameters[0].setName("Foo", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					parameters = func.getParameters();
					parameters[1].setComment("This is a different test comment.");
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func;

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					Parameter[] parameters = func.getParameters();
					parameters[0].setName("Foo", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					parameters = func.getParameters();
					parameters[1].setDataType(new IntegerDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ProgramContext context = resultProgram.getProgramContext();
		Register r12Reg = context.getRegister("r12");

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("Foo", parameters[0].getName());
		assertEquals(r12Reg, parameters[0].getRegister());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals(4, parameters[0].getStackOffset());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("A2", parameters[1].getName());
		assertEquals(8, parameters[1].getStackOffset());
		assertTrue(new IntegerDataType().isEquivalent(parameters[1].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	@Test
	public void testChangeRegParamConflict() throws Exception {

		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
					addParameter(orangesFunction, "A2", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");

					Function pearsFunction =
						createExternalFunction(program, new String[] { "user32.dll", "pears" });
					addParameter(pearsFunction, "B1", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");
					addParameter(pearsFunction, "B2", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");

					Function grapesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "grapes" });
					addParameter(grapesFunction, "C1", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");
					addParameter(grapesFunction, "C2", SourceType.USER_DEFINED, new DWordDataType(),
						"Test Parameter Comment");

					Function berriesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "berries" });
					addParameter(berriesFunction, "D1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
					addParameter(berriesFunction, "D2", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ProgramContext context = program.getProgramContext();
					Function func;

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					changeToRegisterParameter(func, 0, context.getRegister("R1"));

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 1, 0x4);

					func = getExternalFunction(program, new String[] { "user32.dll", "pears" });
					func.getParameter(0).setName("LatestName_0", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "grapes" });
					func.getParameter(1).setDataType(new WordDataType(), SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "berries" });
					func.getParameter(0).setComment("test comment.");
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ProgramContext context = program.getProgramContext();
					Function func;

					func = getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setCustomVariableStorage(true);
					changeToStackParameter(func, 0, 0x4);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setCustomVariableStorage(true);
					changeToRegisterParameter(func, 1, context.getRegister("r2"));

					func = getExternalFunction(program, new String[] { "user32.dll", "pears" });
					func.getParameter(0).setName("NewName_0", SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "grapes" });
					func.getParameter(1)
							.setDataType(new ArrayDataType(new ByteDataType(), 2, 1),
								SourceType.USER_DEFINED);

					func = getExternalFunction(program, new String[] { "user32.dll", "berries" });
					func.getParameter(0).setComment("My sample comment.");
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);// storage change for user32.dll::apples
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);// storage change for user32.dll::oranges
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY });// Name change for user32.dll::pears
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY });// Datatype change for user32.dll::grapes
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY });// Comment change for user32.dll::berries
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter[] parameters = func.getParameters();
		assertEquals(1, parameters.length);
		assertEquals("P1", parameters[0].getName());
		assertEquals(4, parameters[0].getStackOffset());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		Variable[] localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("A1", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("A2", parameters[1].getName());
		assertEquals("r2", parameters[1].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[1].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "pears" });
		parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("NewName_0", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("B2", parameters[1].getName());
		assertEquals("r11", parameters[1].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[1].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "grapes" });
		parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("C1", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertEquals("C2", parameters[1].getName());
		assertEquals("r11l", parameters[1].getRegister().getName());
		assertTrue(
			new ArrayDataType(new ByteDataType(), 2, 1).isEquivalent(parameters[1].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "berries" });
		parameters = func.getParameters();
		assertEquals(2, parameters.length);
		assertEquals("D1", parameters[0].getName());
		assertEquals("r12", parameters[0].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[0].getDataType()));
		assertTrue("My sample comment.".equals(parameters[0].getComment()));
		assertEquals("D2", parameters[1].getName());
		assertEquals("r11", parameters[1].getRegister().getName());
		assertTrue(new DWordDataType().isEquivalent(parameters[1].getDataType()));
		localVariables = func.getLocalVariables();
		assertEquals(0, localVariables.length);
	}

	@Test
	public void testChangeFunctionPurge() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "apples" },
							addr(program, "77db1020"), new ByteDataType(), SourceType.USER_DEFINED);
					assertNotNull(applesFunction);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Function orangesFunction =
						createExternalFunction(program, new String[] { "user32.dll", "oranges" });
					addParameter(orangesFunction, "A1", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
					addParameter(orangesFunction, "A2", SourceType.USER_DEFINED,
						new DWordDataType(), "Test Parameter Comment");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setStackPurgeSize(5);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setStackPurgeSize(3);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function func =
						getExternalFunction(program, new String[] { "user32.dll", "apples" });
					func.setStackPurgeSize(8);

					func = getExternalFunction(program, new String[] { "user32.dll", "oranges" });
					func.setStackPurgeSize(2);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		chooseVariousOptionsForConflictType("Resolve Function Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		Function func = getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		assertEquals(5, func.getStackPurgeSize());

		func = getExternalFunction(resultProgram, new String[] { "user32.dll", "oranges" });
		assertEquals(2, func.getStackPurgeSize());
	}
}
