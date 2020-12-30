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
package ghidra.app.cmd.data;

import static org.junit.Assert.*;

import org.junit.Assert;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;

/**
 * Abstract class that is extended by the CreateDataType tests.
 * It provides ProgramBuilder and Options setup for the tests.
 */
public class AbstractCreateDataTypeModelTest extends AbstractGenericTest {

	protected static DataValidationOptions defaultValidationOptions = new DataValidationOptions();
	protected static DataApplyOptions defaultApplyOptions = new DataApplyOptions();
	protected DataValidationOptions noFollowValidationOptions = new DataValidationOptions();
	protected DataApplyOptions noFollowApplyOptions = new DataApplyOptions();

	private static DataTypeManagerService service;

	protected AbstractCreateDataTypeModelTest() {
		super();
		noFollowValidationOptions.setValidateReferredToData(false);
		noFollowApplyOptions.setFollowData(false);
	}

	/**
	 * Setup DTM service such that the same instance if used across all test methods.
	 * This assumes that a tool is not used and that the DefaultDataTypeManagerService 
	 * is used.
	 */
	protected void setupDTMService(Program program) {
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		if (service != null) {
			setInstanceField("service", analysisMgr, service);
		}
		else {
			service = analysisMgr.getDataTypeManagerService();
			assertTrue("DefaultDataTypeManagerService".equals(service.getClass().getSimpleName()));
			Runtime.getRuntime().addShutdownHook(new ShutdownServiceHook());
		}
	}

	protected void preserveDTMService(Program program) {
		if (program != null) {
			// do not dispose analysis manager since we want to keep DTM service alive
			AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
			setInstanceField("service", analysisMgr, null);
		}
	}

	private class ShutdownServiceHook extends Thread {
		@Override
		public void run() {
			if (service != null) {
				invokeInstanceMethod("dispose", service);
			}
		}
	}

	private void setExecFormatAndCompiler(ProgramBuilder builder) {
		setExecFormatAndCompiler(builder, PeLoader.PE_NAME, CompilerEnum.VisualStudio.toString());
	}

	private void setExecFormatAndCompiler(ProgramBuilder builder, String execFormat,
			String compiler) {
		ProgramDB program = builder.getProgram();
		int txID = program.startTransaction("Setting format and compiler.");
		boolean commit = false;
		try {
			if (execFormat != null) {
				program.setExecutableFormat(execFormat);
			}
			if (compiler != null) {
				program.setCompiler(compiler);
			}
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}
	}

	private void setImageBase(ProgramBuilder builder, long imageBase)
			throws AddressOverflowException, LockException, IllegalStateException {
		ProgramDB program = builder.getProgram();
		int txID = program.startTransaction("Setting image base.");
		boolean commit = false;
		try {
			program.setImageBase(builder.addr(imageBase), true);
			commit = true;
		}
		finally {
			program.endTransaction(txID, commit);
		}
	}

	/**
	 * Creates a 32 bit program builder that can be used for testing.
	 * @return the program builder for a 32 bit VisualStudio x86 PE program.
	 * @throws Exception if it fails to create the ProgramBuilder
	 */
	protected ProgramBuilder build32BitX86() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("test32BitX86", ProgramBuilder._X86, "windows", null);
		setExecFormatAndCompiler(builder);
		setImageBase(builder, 0x01000000L);
		builder.createMemory(".text", "0x01001000", 0x2000);
		builder.createMemory(".rdata", "0x01003000", 0x2000);
		builder.createMemory(".data", "0x01005000", 0x2000);
		setupDTMService(builder.getProgram());
		setupDummy32TypeInfo(builder);
		return builder;
	}

	/**
	 * Creates a 64 bit program builder that can be used for testing.
	 * @return the program builder for a 64 bit VisualStudio x86 PE program.
	 * @throws Exception if it fails to create the ProgramBuilder
	 */
	protected ProgramBuilder build64BitX86() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("test64BitX86", ProgramBuilder._X64, "windows", null);
		setExecFormatAndCompiler(builder);
		setImageBase(builder, 0x101000000L);
		builder.createMemory(".text", "0x101001000", 0x2000);
		builder.createMemory(".rdata", "0x101003000", 0x2000);
		builder.createMemory(".data", "0x101005000", 0x2000);
		setupDTMService(builder.getProgram());
		setupDummy64TypeInfo(builder);
		return builder;
	}

	/**
	 * Creates a 64 bit program builder that can be used for testing.
	 * @return the program builder for a 64 bit VisualStudio x86 PE program.
	 * @throws Exception if it fails to create the ProgramBuilder
	 */
	protected ProgramBuilder build64BitX86Clang() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("test64BitX86", ProgramBuilder._X64, "clangwindows", null);
		setExecFormatAndCompiler(builder, PeLoader.PE_NAME, "clang:unknown");
		setImageBase(builder, 0x101000000L);
		builder.createMemory(".text", "0x101001000", 0x2000);
		builder.createMemory(".rdata", "0x101003000", 0x2000);
		builder.createMemory(".data", "0x101005000", 0x2000);
		setupDTMService(builder.getProgram());
		setupDummy64TypeInfo(builder);
		return builder;
	}

	/**
	 * Creates a 64 bit program builder that can be used for testing.
	 * @return the program builder for a 64 bit non-VisualStudio x86 PE program.
	 * @throws Exception if it fails to create the ProgramBuilder
	 */
	protected ProgramBuilder build64BitX86NonVS() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("test64BitX86Unknown", ProgramBuilder._X64, "windows", null);
		setExecFormatAndCompiler(builder, PeLoader.PE_NAME, null);
		setImageBase(builder, 0x101000000L);
		builder.createMemory(".text", "0x101001000", 0x2000);
		builder.createMemory(".rdata", "0x101003000", 0x2000);
		builder.createMemory(".data", "0x101005000", 0x2000);
		setupDummy64TypeInfo(builder);
		return builder;
	}
	
	
	protected void setupDummy32TypeInfo(ProgramBuilder builder) throws Exception {
		builder.setBytes("0x01005000", getHexAddress32AsByteString("0x01004000", false));
		builder.setBytes("0x01005004", getHexAddress32AsByteString("0x00000000", false));
		builder.setBytes("0x01005008", RttiUtil.TYPE_INFO_STRING.getBytes());
		
		builder.setBytes("0x01004000", getHexAddress32AsByteString("0x01008000", false));
	}
	
	protected void setupDummy64TypeInfo(ProgramBuilder builder) throws Exception {
		builder.setBytes("0x101005000", getHexAddress64AsByteString("0x101006000", false));
		builder.setBytes("0x101005008", getHexAddress64AsByteString("0x00000000", false));
		builder.setBytes("0x101005010", RttiUtil.TYPE_INFO_STRING.getBytes());
		builder.setBytes("0x101006000", getHexAddress64AsByteString("0x101006080", false));
	}

	protected void setupCode32Bytes(ProgramBuilder builder, String address) throws Exception {
		String byteString = "6a 01" // push
			+ " 83 ec 20" // sub
			+ " 8b e5" // mov
			+ " 5d" // pop
			+ " c3"; // ret
		builder.setBytes(address, byteString, false);
	}

	protected void setupCode32Instructions(ProgramBuilder builder, String address)
			throws Exception {
		String byteString = "6a 01" // push
			+ " 83 ec 20" // sub
			+ " 8b e5" // mov
			+ " 5d" // pop
			+ " c3"; // ret
		builder.setBytes(address, byteString, true);
	}

	@SuppressWarnings("unused")
	protected void setupCode32Data(ProgramBuilder builder, String address) throws Exception {
		setupCode32Bytes(builder, address);
		builder.applyDataType(address, new WordDataType());
	}

	protected void setupCode64Bytes(ProgramBuilder builder, String address) throws Exception {
		String byteString = "40 55" // push
			+ " 48 83 ec 20" // sub
			+ " 48 8b ea" // mov
			+ " 5d" // pop
			+ " c3"; // ret
		builder.setBytes(address, byteString, false);
	}

	protected void setupCode64Instructions(ProgramBuilder builder, String address)
			throws Exception {
		String byteString = "40 55" // push
			+ " 48 83 ec 20" // sub
			+ " 48 8b ea" // mov
			+ " 5d" // pop
			+ " c3"; // ret
		builder.setBytes(address, byteString, true);
	}

	@SuppressWarnings("unused")
	protected void setupCode64Data(ProgramBuilder builder, String address) throws Exception {
		setupCode64Bytes(builder, address);
		builder.applyDataType(address, new WordDataType());
	}

	protected String getHexAddressAsIbo32ByteString(ProgramBuilder builder, String hexAddress,
			boolean bigEndian) {
		Program program = builder.getProgram();
		Address imageBase = program.getImageBase();
		Address address = builder.addr(hexAddress);
		long offset = address.subtract(imageBase);
		return getIntAsByteString((int) offset, bigEndian);
	}

	protected String getIntAsByteString(int value, boolean bigEndian) {
		String hexString = Integer.toHexString(value);
		int length = hexString.length();
		if (length > 8) {
			throw new IllegalArgumentException("Value exceeds 8 hex digits.");
		}
		int leadingZeros = 8 - length;
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < leadingZeros; i++) {
			buf.append('0');
		}
		buf.append(hexString);
		String hexDigits = buf.toString();
		return getByteString(bigEndian, hexDigits);
	}

	protected String getHexAddress32AsByteString(String hexAddress, boolean bigEndian) {
		return getHexAddressAsByteString(hexAddress, bigEndian, 8);
	}

	protected String getHexAddress64AsByteString(String hexAddress, boolean bigEndian) {
		return getHexAddressAsByteString(hexAddress, bigEndian, 16);
	}

	protected String getHexAddressAsByteString(String hexAddress, boolean bigEndian,
			int numHexDigits) {
		int indexOf = hexAddress.indexOf("0x");
		if (indexOf != 0) {
			throw new IllegalArgumentException("Hex address strings must start with 0x.");
		}
		String hexDigits = hexAddress.substring(2, hexAddress.length());
		int hexLength = hexDigits.length();
		if (hexLength > numHexDigits) {
			throw new IllegalArgumentException(
				"hexAddress can't be more than " + numHexDigits + " digits.");
		}
		int missingZeros = numHexDigits - hexLength;
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < missingZeros; i++) {
			buf.append('0');
		}
		buf.append(hexDigits);
		String string = buf.toString();
		return getByteString(bigEndian, string);
	}

//	protected String getHexAddressAsByteString(String hexAddress, boolean bigEndian) {
//		int indexOf = hexAddress.indexOf("0x");
//		if (indexOf != 0) {
//			throw new IllegalArgumentException("Hex address strings must start with 0x.");
//		}
//		String hexDigits = hexAddress.substring(2, hexAddress.length());
//		return getByteString(bigEndian, hexDigits);
//	}

	protected String getByteString(boolean bigEndian, String hexDigits) {
		if (hexDigits.length() % 2 == 1) {
			hexDigits = "0" + hexDigits;
		}
		StringBuffer buf = new StringBuffer();
		int numPairs = hexDigits.length() / 2;
		for (int i = numPairs - 1; i >= 0; i--) {
			int beginIndex = i * 2;
			int endIndex = beginIndex + 2;
			String next2Digits = hexDigits.substring(beginIndex, endIndex);
			if (bigEndian) {
				if (buf.length() > 0) {
					buf.insert(0, ' ');
				}
				buf.insert(0, next2Digits);
			}
			else {
				if (buf.length() > 0) {
					buf.append(' ');
				}
				buf.append(next2Digits);
			}
		}
		return buf.toString();
	}

	protected void checkArrayData(ProgramDB program, long address, DataType elementDt,
			int numElements) {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(addr(program, address));
		DataType dataType = data.getDataType();
		if (!(dataType instanceof Array)) {
			fail("Data type " + dataType.getName() + " isn't an array.");
		}
		Array array = (Array) dataType;
		assertEquals(numElements, array.getNumElements());
		String name = dataType.getName();
		assertEquals(elementDt.getName() + "[" + numElements + "]", name);
		int expectedDtLength = elementDt.getLength() * numElements;
		assertEquals(expectedDtLength, expectedDtLength);

		DataType baseDataType = array.getDataType();
		assertTrue(baseDataType.isEquivalent(elementDt));
	}

	protected void checkSimpleData(ProgramDB program, long address, DataType elementDt) {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(addr(program, address));
		DataType dataType = data.getDataType();
		String name = dataType.getName();
		assertEquals(elementDt.getName(), name);
		int expectedDtLength = elementDt.getLength();
		assertEquals(expectedDtLength, expectedDtLength);
		assertTrue(dataType.isEquivalent(elementDt));
	}

	protected void CheckTypeDefOnStructureData(ProgramDB program, long address, String expectedName,
			String[] expectedFieldNames, int expectedDtLength) {
		CheckStructureData(program, address, expectedName, expectedFieldNames, null,
			expectedDtLength, true);
	}

	protected void CheckStructureData(ProgramDB program, long address, String expectedName,
			String[] expectedFieldNames, int expectedDtLength) {
		CheckStructureData(program, address, expectedName, expectedFieldNames, null,
			expectedDtLength, false);
	}

	protected void CheckStructureData(ProgramDB program, long address, String expectedName,
			String[] expectedFieldNames, String flexArrayName, int expectedDtLength) {
		CheckStructureData(program, address, expectedName, expectedFieldNames, flexArrayName,
			expectedDtLength, false);
	}

	protected void CheckStructureData(ProgramDB program, long address, String expectedName,
			String[] expectedFieldNames, String flexArrayName, int expectedDtLength,
			boolean isTypeDefOfStructure) {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(addr(program, address));
		DataType dataType = data.getDataType();
		String name = dataType.getName();
		assertEquals(expectedName, name);
		assertEquals(expectedDtLength, dataType.getLength());

		DataType baseDataType = dataType;
		if (isTypeDefOfStructure) {
			assertTrue("DataType " + name + " wasn't a TypeDef.", dataType instanceof TypeDef);
			baseDataType = ((TypeDef) dataType).getBaseDataType();
		}
		assertTrue("DataType " + name + "'s base data type wasn't a Structure.",
			baseDataType instanceof Structure);
		Structure structure = (Structure) baseDataType;
		assertEquals("Mismatch in expected structure component count: " + name,
			expectedFieldNames.length, structure.getNumComponents());
		DataTypeComponent[] components = structure.getComponents();
		for (int i = 0; i < components.length; i++) {
			assertEquals(
				"Expected component " + i + " to be named " + expectedFieldNames[i] + " but was " +
					components[i].getFieldName(),
				expectedFieldNames[i], components[i].getFieldName());
		}
		if (flexArrayName != null) {
			DataTypeComponent flexibleArrayComponent = structure.getFlexibleArrayComponent();
			assertNotNull("Structure does not contain flexible array: " + name,
				flexibleArrayComponent);
			assertEquals(
				"Expected flexible array named " + flexArrayName + " but was " +
					flexibleArrayComponent.getFieldName(),
				flexArrayName, flexibleArrayComponent.getFieldName());
		}
		else {
			assertFalse("Structure contains unexpected flexible array component: " + name,
				structure.hasFlexibleArrayComponent());
		}
	}

	protected void CheckDynamicStructureData(ProgramDB program, long address, String expectedName,
			String[] expectedFieldNames, int expectedDtLength) {

		Listing listing = program.getListing();
		Address dataAddress = addr(program, address);
		Data data = listing.getDataAt(dataAddress);
		DataType dataType = data.getDataType();
		String name = dataType.getName();
		assertEquals(expectedName, name);
		assertEquals(expectedDtLength, data.getLength());

		assertTrue("DataType " + dataType.getName() + " isn't a DynamicDataType.",
			dataType instanceof DynamicDataType);
		DynamicDataType dynamicDt = (DynamicDataType) dataType;
		DumbMemBufferImpl memBuffer = new DumbMemBufferImpl(program.getMemory(), dataAddress);
		assertEquals(expectedFieldNames.length, dynamicDt.getNumComponents(memBuffer));
		DataTypeComponent[] components = dynamicDt.getComponents(memBuffer);
		for (int i = 0; i < components.length; i++) {
			assertEquals(
				"Expected component " + i + " to be named " + expectedFieldNames[i] + " but was " +
					components[i].getFieldName(),
				expectedFieldNames[i], components[i].getFieldName());
		}
	}

	protected void checkNoData(ProgramDB program, long address) {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(addr(program, address));
		assertEquals(DefaultDataType.dataType, data.getDataType());
	}

	protected Address addr(Program program, long address) {
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
		return defaultAddressSpace.getAddress(address);
	}

	protected void checkInvalidModel(AbstractCreateDataTypeModel model, String errorMessage) {

		try {
			model.validate();
			Assert.fail("Model validation should have failed.");
		}
		catch (InvalidDataTypeException e) {
			// Should fail validation with expected error message.
			assertEquals(errorMessage, e.getMessage());
		}
	}

	protected void checkTypeDescriptorData(ProgramDB program, long address, int structLength,
			int nameArrayLength, String expectedTypeName) {
		CheckStructureData(program, address, "TypeDescriptor", new String[] { "pVFTable", "spare" },
			"name", structLength);
		checkTypeName(program, address, expectedTypeName);
	}

	private void checkTypeName(ProgramDB program, long address, String expectedTypeName) {
		TypeDescriptorModel typeDescriptorModel =
			new TypeDescriptorModel(program, addr(program, address), defaultValidationOptions);
		try {
			String typeName = typeDescriptorModel.getTypeName();
			assertEquals(expectedTypeName, typeName);
		}
		catch (InvalidDataTypeException e) {
			fail("Couldn't get type name for TypeDescriptor @ " + address);
		}
	}

}
