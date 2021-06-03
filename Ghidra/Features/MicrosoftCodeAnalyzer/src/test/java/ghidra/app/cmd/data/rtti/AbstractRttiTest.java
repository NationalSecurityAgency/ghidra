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
package ghidra.app.cmd.data.rtti;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import ghidra.app.cmd.data.AbstractCreateDataTypeModelTest;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

/**
 * Abstract class that is extended by the RTTI tests.
 * It provides setup and validation methods for the tests.
 */
class AbstractRttiTest extends AbstractCreateDataTypeModelTest {

	protected void setupRtti4_32(ProgramBuilder builder, long address, int signature, int offset,
			int cdOffset, String typeDescriptorAddress, String classDescriptorAddress)
			throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address signatureAddr = builder.addr(address);
		Address offsetAddr = builder.addr(address + 4);
		Address cdOffsetAddr = builder.addr(address + 8);
		Address typeDescriptorAddr = builder.addr(address + 12);
		Address classDescriptorAddr = builder.addr(address + 16);
		builder.setBytes(signatureAddr.toString(), getIntAsByteString(signature, bigEndian));
		builder.setBytes(offsetAddr.toString(), getIntAsByteString(offset, bigEndian));
		builder.setBytes(cdOffsetAddr.toString(), getIntAsByteString(cdOffset, bigEndian));
		String typeDescriptorBytes = getHexAddress32AsByteString(typeDescriptorAddress, bigEndian);
		builder.setBytes(typeDescriptorAddr.toString(), typeDescriptorBytes);
		String classDescriptorBytes =
			getHexAddress32AsByteString(classDescriptorAddress, bigEndian);
		builder.setBytes(classDescriptorAddr.toString(), classDescriptorBytes);
	}

	protected void setupRtti4_64(ProgramBuilder builder, long address, int signature, int offset,
			int cdOffset, String typeDescriptorAddress, String classDescriptorAddress)
			throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address signatureAddr = builder.addr(address);
		Address offsetAddr = builder.addr(address + 4);
		Address cdOffsetAddr = builder.addr(address + 8);
		Address typeDescriptorAddr = builder.addr(address + 12);
		Address classDescriptorAddr = builder.addr(address + 16);
		builder.setBytes(signatureAddr.toString(), getIntAsByteString(signature, bigEndian));
		builder.setBytes(offsetAddr.toString(), getIntAsByteString(offset, bigEndian));
		builder.setBytes(cdOffsetAddr.toString(), getIntAsByteString(cdOffset, bigEndian));
		String typeDescriptorBytes =
			getHexAddressAsIbo32ByteString(builder, typeDescriptorAddress, bigEndian);
		builder.setBytes(typeDescriptorAddr.toString(), typeDescriptorBytes);
		String classDescriptorBytes =
			getHexAddressAsIbo32ByteString(builder, classDescriptorAddress, bigEndian);
		builder.setBytes(classDescriptorAddr.toString(), classDescriptorBytes);
	}

	protected void setupRtti3_32(ProgramBuilder builder, long address, int signature,
			int attributes, int numBaseClasses, String baseClassArrayAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address signatureAddr = builder.addr(address);
		Address attributesAddr = builder.addr(address + 4);
		Address numBaseClassesAddr = builder.addr(address + 8);
		Address baseClassArrayAddr = builder.addr(address + 12);
		builder.setBytes(signatureAddr.toString(), getIntAsByteString(signature, bigEndian));
		builder.setBytes(attributesAddr.toString(), getIntAsByteString(attributes, bigEndian));
		builder.setBytes(numBaseClassesAddr.toString(),
			getIntAsByteString(numBaseClasses, bigEndian));
		builder.setBytes(baseClassArrayAddr.toString(),
			getHexAddress32AsByteString(baseClassArrayAddress, bigEndian));
	}

	protected void setupRtti3_64(ProgramBuilder builder, long address, int signature,
			int attributes, int numBaseClasses, String baseClassArrayAddress) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address signatureAddr = builder.addr(address);
		Address attributesAddr = builder.addr(address + 4);
		Address numBaseClassesAddr = builder.addr(address + 8);
		Address baseClassArrayAddr = builder.addr(address + 12);
		builder.setBytes(signatureAddr.toString(), getIntAsByteString(signature, bigEndian));
		builder.setBytes(attributesAddr.toString(), getIntAsByteString(attributes, bigEndian));
		builder.setBytes(numBaseClassesAddr.toString(),
			getIntAsByteString(numBaseClasses, bigEndian));
		String baseClassArrayAddrBytes =
			getHexAddressAsIbo32ByteString(builder, baseClassArrayAddress, bigEndian);
		builder.setBytes(baseClassArrayAddr.toString(), baseClassArrayAddrBytes);
	}

	protected void setupRtti2_32(ProgramBuilder builder, long address,
			String[] baseClassDescriptorAddresses) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		for (int i = 0; i < baseClassDescriptorAddresses.length; i++) {
			Address addr = builder.addr(address + (i * 4));
			builder.setBytes(addr.toString(),
				getHexAddress32AsByteString(baseClassDescriptorAddresses[i], bigEndian));
		}
	}

	protected void setupRtti2_64(ProgramBuilder builder, long address,
			String[] baseClassDescriptorAddresses) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		for (int i = 0; i < baseClassDescriptorAddresses.length; i++) {
			Address addr = builder.addr(address + (i * 4));
			builder.setBytes(addr.toString(), getHexAddressAsIbo32ByteString(builder,
				baseClassDescriptorAddresses[i], bigEndian));
		}
	}

	protected void setupRtti1_32(ProgramBuilder builder, long address, String typeDescriptorAddress,
			int numContainedBases, int mdisp, int pdisp, int vdisp, int attributes,
			String classHierarchyAddress) throws Exception {

		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address typeDescriptorAddr = builder.addr(address);
		Address numContainedBasesAddr = builder.addr(address + 4);
		Address mDispAddr = builder.addr(address + 8);
		Address pDispAddr = builder.addr(address + 12);
		Address vDispAddr = builder.addr(address + 16);
		Address attributesAddr = builder.addr(address + 20);
		Address classHierarchyAddr = builder.addr(address + 24);
		builder.setBytes(typeDescriptorAddr.toString(),
			getHexAddress32AsByteString(typeDescriptorAddress, bigEndian));
		builder.setBytes(numContainedBasesAddr.toString(),
			getIntAsByteString(numContainedBases, bigEndian));
		builder.setBytes(mDispAddr.toString(), getIntAsByteString(mdisp, bigEndian));
		builder.setBytes(pDispAddr.toString(), getIntAsByteString(pdisp, bigEndian));
		builder.setBytes(vDispAddr.toString(), getIntAsByteString(vdisp, bigEndian));
		builder.setBytes(attributesAddr.toString(), getIntAsByteString(attributes, bigEndian));
		builder.setBytes(classHierarchyAddr.toString(),
			getHexAddress32AsByteString(classHierarchyAddress, bigEndian));
	}

	protected void setupRtti1_64(ProgramBuilder builder, long address, String typeDescriptorAddress,
			int numContainedBases, int mdisp, int pdisp, int vdisp, int attributes,
			String classHierarchyAddress) throws Exception {

		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address typeDescriptorAddr = builder.addr(address);
		Address numContainedBasesAddr = builder.addr(address + 4);
		Address mDispAddr = builder.addr(address + 8);
		Address pDispAddr = builder.addr(address + 12);
		Address vDispAddr = builder.addr(address + 16);
		Address attributesAddr = builder.addr(address + 20);
		Address classHierarchyAddr = builder.addr(address + 24);
		builder.setBytes(typeDescriptorAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, typeDescriptorAddress, bigEndian));
		builder.setBytes(numContainedBasesAddr.toString(),
			getIntAsByteString(numContainedBases, bigEndian));
		builder.setBytes(mDispAddr.toString(), getIntAsByteString(mdisp, bigEndian));
		builder.setBytes(pDispAddr.toString(), getIntAsByteString(pdisp, bigEndian));
		builder.setBytes(vDispAddr.toString(), getIntAsByteString(vdisp, bigEndian));
		builder.setBytes(attributesAddr.toString(), getIntAsByteString(attributes, bigEndian));
		builder.setBytes(classHierarchyAddr.toString(),
			getHexAddressAsIbo32ByteString(builder, classHierarchyAddress, bigEndian));
	}

	protected void setupRtti0_32(ProgramBuilder builder, long address, String tableAddress,
			String spareAddress, String name) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address tableAddressCompAddr = builder.addr(address);
		Address spareAddressCompAddr = builder.addr(address + 4);
		Address nameCompAddr = builder.addr(address + 8);
		builder.setBytes(tableAddressCompAddr.toString(),
			getHexAddress32AsByteString(tableAddress, bigEndian));
		builder.setBytes(spareAddressCompAddr.toString(),
			getHexAddress32AsByteString(spareAddress, bigEndian));
		builder.setBytes(nameCompAddr.toString(), name.getBytes());
	}

	protected void setupRtti0_64(ProgramBuilder builder, long address, String tableAddress,
			String spareAddress, String name) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address tableAddressCompAddr = builder.addr(address);
		Address spareAddressCompAddr = builder.addr(address + 8);
		Address nameCompAddr = builder.addr(address + 16);
		builder.setBytes(tableAddressCompAddr.toString(),
			getHexAddress64AsByteString(tableAddress, bigEndian));
		builder.setBytes(spareAddressCompAddr.toString(),
			getHexAddress64AsByteString(spareAddress, bigEndian));
		builder.setBytes(nameCompAddr.toString(), name.getBytes());
	}

	protected void setupVfTable_32(ProgramBuilder builder, long address, String metaPtrString,
			String[] rtti1Addresses) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address metaPointerAddr = builder.addr(address);
		long startOffset = address + 4;
		builder.setBytes(metaPointerAddr.toString(),
			getHexAddress32AsByteString(metaPtrString, bigEndian));
		for (int i = 0; i < rtti1Addresses.length; i++) {
			Address rtti1Addr = builder.addr(startOffset + (i * 4));
			builder.setBytes(rtti1Addr.toString(),
				getHexAddress32AsByteString(rtti1Addresses[i], bigEndian));
		}
	}

	protected void setupVfTable_64(ProgramBuilder builder, long address, String metaPtrString,
			String[] rtti1Addresses) throws Exception {
		ProgramDB program = builder.getProgram();
		boolean bigEndian = program.getCompilerSpec().getDataOrganization().isBigEndian();
		Address metaPointerAddr = builder.addr(address);
		long startOffset = address + 8;
		builder.setBytes(metaPointerAddr.toString(),
			getHexAddress64AsByteString(metaPtrString, bigEndian));
		for (int i = 0; i < rtti1Addresses.length; i++) {
			Address rtti1Addr = builder.addr(startOffset + (i * 8));
			builder.setBytes(rtti1Addr.toString(),
				getHexAddress64AsByteString(rtti1Addresses[i], bigEndian));
		}
	}

	protected VfTableModel checkVfTableNoFollowModel(ProgramDB program, long metaPointerAddress,
			long rtti4Address, long vfTableAddress, long[] vfAddresses)
			throws InvalidDataTypeException {
		return doCheckVfTableModel(program, metaPointerAddress, rtti4Address, vfTableAddress,
			vfAddresses, noFollowValidationOptions);
	}

	protected VfTableModel checkVfTableModel(ProgramDB program, long metaPointerAddress,
			long rtti4Address, long vfTableAddress, long[] vfAddresses)
			throws InvalidDataTypeException {
		return doCheckVfTableModel(program, metaPointerAddress, rtti4Address, vfTableAddress,
			vfAddresses, defaultValidationOptions);
	}

	protected VfTableModel doCheckVfTableModel(ProgramDB program, long metaPointerAddress,
			long rtti4Address, long vfTableAddress, long[] vfAddresses,
			DataValidationOptions validationOptions) throws InvalidDataTypeException {

		Address addressMetaPointer = addr(program, metaPointerAddress);
		Address addressRtti4 = getAbsoluteAddress(program, addressMetaPointer);
		assertEquals(addr(program, rtti4Address), addressRtti4);
		// Check vf table
		Address addressVfTable = addr(program, vfTableAddress);
		VfTableModel vfTableModel = new VfTableModel(program, addressVfTable, validationOptions);
		vfTableModel.validate();
		assertEquals(addressVfTable, vfTableModel.getAddress());
		int numVfTableEntries = vfAddresses.length;
		assertEquals(numVfTableEntries, vfTableModel.getElementCount());
		for (int i = 0; i < numVfTableEntries; i++) {
			assertEquals(addr(program, vfAddresses[i]), vfTableModel.getVirtualFunctionPointer(i));
		}
		return vfTableModel;
	}

	protected TypeDescriptorModel checkRtti0ModelNoFollow(ProgramDB program, long rtti0Address,
			long vfTableAddress, long spareAddress, String typeName)
			throws InvalidDataTypeException, UndefinedValueException {
		return doCheckRtti0Model(program, rtti0Address, vfTableAddress, spareAddress, typeName,
			noFollowValidationOptions);
	}

	protected TypeDescriptorModel checkRtti0Model(ProgramDB program, long rtti0Address,
			long vfTableAddress, long spareAddress, String typeName)
			throws InvalidDataTypeException, UndefinedValueException {
		return doCheckRtti0Model(program, rtti0Address, vfTableAddress, spareAddress, typeName,
			defaultValidationOptions);
	}

	protected TypeDescriptorModel doCheckRtti0Model(ProgramDB program, long rtti0Address,
			long vfTableAddress, long spareAddress, String typeName,
			DataValidationOptions validationOptions)
			throws InvalidDataTypeException, UndefinedValueException {

		Address addressRtti0 = addr(program, rtti0Address);
		TypeDescriptorModel model0 =
			new TypeDescriptorModel(program, addressRtti0, validationOptions);
		model0.validate();
		assertEquals(addressRtti0, model0.getAddress());
		assertEquals(addr(program, vfTableAddress), model0.getVFTableAddress());
		Address expectedSpareAddress = (spareAddress == 0L) ? null : addr(program, spareAddress);
		assertEquals(expectedSpareAddress, model0.getSpareDataAddress());
		assertEquals(typeName, model0.getTypeName());
		return model0;
	}

	protected Rtti1Model checkRtti1ModelNoFollow(ProgramDB program, long rtti1Address,
			long rtti0Address, int numBases, int mDisp, int pDisp, int vDisp, int attributes,
			long rtti3Address) throws InvalidDataTypeException {
		return doCheckRtti1Model(program, rtti1Address, rtti0Address, numBases, mDisp, pDisp, vDisp,
			attributes, rtti3Address, noFollowValidationOptions);
	}

	protected Rtti1Model checkRtti1Model(ProgramDB program, long rtti1Address, long rtti0Address,
			int numBases, int mDisp, int pDisp, int vDisp, int attributes, long rtti3Address)
			throws InvalidDataTypeException {
		return doCheckRtti1Model(program, rtti1Address, rtti0Address, numBases, mDisp, pDisp, vDisp,
			attributes, rtti3Address, defaultValidationOptions);
	}

	protected Rtti1Model doCheckRtti1Model(ProgramDB program, long rtti1Address, long rtti0Address,
			int numBases, int mDisp, int pDisp, int vDisp, int attributes, long rtti3Address,
			DataValidationOptions validationOptions) throws InvalidDataTypeException {

		Address addressRtti1 = addr(program, rtti1Address);
		Rtti1Model model1 = new Rtti1Model(program, addressRtti1, validationOptions);
		model1.validate();
		assertEquals(addressRtti1, model1.getAddress());
		assertEquals(addr(program, rtti0Address), model1.getRtti0Address());
		assertEquals(numBases, model1.getNumBases());
		assertEquals(mDisp, model1.getMDisp());
		assertEquals(pDisp, model1.getPDisp());
		assertEquals(vDisp, model1.getVDisp());
		assertEquals(attributes, model1.getAttributes());
		Address addressRtti3 = addr(program, rtti3Address);
		boolean shouldValidateReferredToData = validationOptions.shouldValidateReferredToData();
		if (shouldValidateReferredToData) {
			Rtti3Model model3 = new Rtti3Model(program, addressRtti3, validationOptions);
			model3.validate();
			assertEquals(addressRtti3, model3.getAddress());
		}
		return model1;
	}

	protected Rtti2Model checkRtti2ModelNoFollow(ProgramDB program, long rtti2Address,
			long[] rtti1Addresses) throws InvalidDataTypeException {
		return doCheckRtti2Model(program, rtti2Address, rtti1Addresses, noFollowValidationOptions);
	}

	protected Rtti2Model checkRtti2Model(ProgramDB program, long rtti2Address,
			long[] rtti1Addresses) throws InvalidDataTypeException {
		return doCheckRtti2Model(program, rtti2Address, rtti1Addresses, defaultValidationOptions);
	}

	protected Rtti2Model doCheckRtti2Model(ProgramDB program, long rtti2Address,
			long[] rtti1Addresses, DataValidationOptions validationOptions)
			throws InvalidDataTypeException {

		Address addressRtti2 = addr(program, rtti2Address);
		int numEntries = rtti1Addresses.length;
		Rtti2Model model2 = new Rtti2Model(program, numEntries, addressRtti2, validationOptions);
		model2.validate();
		assertEquals(addressRtti2, model2.getAddress());
		for (int i = 0; i < numEntries; i++) {
			assertEquals(addr(program, rtti1Addresses[i]), model2.getRtti1Address(i)); // each RTTI 1 pointer.
		}
		return model2;
	}

	protected Rtti3Model checkRtti3ModelNoFollow(Program program, long rtti3Address, int signature,
			int attributes, int rtti1Count, long rtti2Address) throws InvalidDataTypeException {
		return doCheckRtti3Model(program, rtti3Address, signature, attributes, rtti1Count,
			rtti2Address, noFollowValidationOptions);
	}

	protected Rtti3Model checkRtti3Model(Program program, long rtti3Address, int signature,
			int attributes, int rtti1Count, long rtti2Address) throws InvalidDataTypeException {
		return doCheckRtti3Model(program, rtti3Address, signature, attributes, rtti1Count,
			rtti2Address, defaultValidationOptions);
	}

	protected Rtti3Model doCheckRtti3Model(Program program, long rtti3Address, int signature,
			int attributes, int rtti1Count, long rtti2Address,
			DataValidationOptions validationOptions) throws InvalidDataTypeException {

		Address addressRtti3 = addr(program, rtti3Address);
		Rtti3Model model3 = new Rtti3Model(program, addressRtti3, validationOptions);
		model3.validate();
		assertEquals(addressRtti3, model3.getAddress());
		assertEquals(signature, model3.getSignature());
		assertEquals(attributes, model3.getAttributes());
		assertEquals(rtti1Count, model3.getRtti1Count());
		assertEquals(addr(program, rtti2Address), model3.getRtti2Address());
		return model3;
	}

	protected Rtti4Model checkRtti4ModelNoFollow(Program program, long rtti4Address, int signature,
			int vbTableOffset, int constructorOffset, long rtti0Address, long rtti3Address)
			throws InvalidDataTypeException {
		return doCheckRtti4Model(program, rtti4Address, signature, vbTableOffset, constructorOffset,
			rtti0Address, rtti3Address, noFollowValidationOptions);
	}

	protected Rtti4Model checkRtti4Model(Program program, long rtti4Address, int signature,
			int vbTableOffset, int constructorOffset, long rtti0Address, long rtti3Address)
			throws InvalidDataTypeException {
		return doCheckRtti4Model(program, rtti4Address, signature, vbTableOffset, constructorOffset,
			rtti0Address, rtti3Address, defaultValidationOptions);
	}

	protected Rtti4Model doCheckRtti4Model(Program program, long rtti4Address, int signature,
			int vbTableOffset, int constructorOffset, long rtti0Address, long rtti3Address,
			DataValidationOptions validationOptions) throws InvalidDataTypeException {

		Address addressRtti4 = addr(program, rtti4Address);
		Rtti4Model model4 = new Rtti4Model(program, addressRtti4, validationOptions);
		model4.validate();
		assertEquals(addressRtti4, model4.getAddress());
		assertEquals(signature, model4.getSignature());
		assertEquals(vbTableOffset, model4.getVbTableOffset());
		assertEquals(constructorOffset, model4.getConstructorOffset());
		assertEquals(addr(program, rtti0Address), model4.getRtti0Address());
		assertEquals(addr(program, rtti3Address), model4.getRtti3Address());
		return model4;
	}

	protected void setupRtti32CompleteFlow(ProgramBuilder builder) throws Exception {

		setupRtti32Base(builder);
		setupRtti32Shape(builder);
		setupRtti32Circle(builder);
		setupInstructions32(builder);
	}

	protected void setupInstructions32(ProgramBuilder builder) throws Exception {
		// instructions
		setupCode32Bytes(builder, "0x01001200");
		setupCode32Instructions(builder, "0x01001214");
		setupCode32Bytes(builder, "0x01001230");
		setupCode32Bytes(builder, "0x01001260");
		setupCode32Instructions(builder, "0x01001280");
		setupCode32Bytes(builder, "0x010012a0");
	}

	protected void setupRtti32Circle(ProgramBuilder builder) throws Exception {
		// ---- Circle ----
		// rtti4:  01003240 - 01003253
		// rtti3:  01003268 - 01003277
		// rtti2:  01003290 - 0100329b
		// rtti1:  010032a8 - 010032c3
		// rtti0:  010033e0 - 010033f3
		// vfTbl:  010031f0 - 010031fb
		//
		setupRtti4_32(builder, 0x01003240L, 0, 0, 0, "0x010053e0", "0x01003268"); // 20 bytes
		setupRtti3_32(builder, 0x01003268L, 0, 0, 3, "0x01003290"); // 16 bytes
		setupRtti2_32(builder, 0x01003290L,
			new String[] { "0x010032a8", "0x010033c4", "0x010033a8" }); // 12 bytes
		setupRtti1_32(builder, 0x010032a8L, "0x010053e0", 0, 0, 0xffffffff, 0, 0x40, "0x01003268"); // 28 bytes
		setupRtti0_32(builder, 0x010053e0L, "0x01003280", "0x00000000", ".?AVCircle@@"); // 4 + 4 + 13 bytes + 3 align = 24
		setupVfTable_32(builder, 0x010031f0L, "0x01003240",
			new String[] { "0x01001260", "0x010012a0" });  // 4 + (2 * 4) bytes = 12
	}

	protected void setupRtti32Shape(ProgramBuilder builder) throws Exception {
		// ---- Shape ----
		//
		// rtti4:  01003354 - 01003367
		// rtti3:  01003378 - 01003387
		// rtti2:  01003394 - 0100339b
		// rtti1:  010033c4 - 010033df
		// rtti0:  01003214 - 0100322b
		// vfTbl:  01003230 - 0100323b
		//
		setupRtti4_32(builder, 0x01003354L, 0, 0, 0, "0x01005214", "0x01003378"); // 20 bytes
		setupRtti3_32(builder, 0x01003378L, 0, 0, 2, "0x01003394"); // 16 bytes
		setupRtti2_32(builder, 0x01003394L, new String[] { "0x010033c4", "0x010033a8" }); // 8 bytes
		setupRtti1_32(builder, 0x010033c4L, "0x01005214", 0, 0, 0xffffffff, 0, 0x40, "0x01003378"); // 28 bytes
		setupRtti0_32(builder, 0x01005214L, "0x01003280", "0x00000000", ".?AVShape@@"); // 4 + 4 + 12 bytes + 0 align = 20
		setupVfTable_32(builder, 0x01003230L, "0x01003354",
			new String[] { "0x01001214", "0x01001230" }); // 4 + (2 * 4) bytes = 12
	}

	protected void setupRtti32Base(ProgramBuilder builder) throws Exception {
		// ---- Base ----
		// rtti4:  01003340 - 01003353
		// rtti3:  01003368 - 01003377
		// rtti2:  01003390 - 01003393
		// rtti1:  010033a8 - 010033c3
		// rtti0:  01003200 - 01003213
		// vfTbl:  010032f0 - 010032fb
		//
		setupRtti4_32(builder, 0x01003340L, 0, 0, 0, "0x01005200", "0x01003368"); // 20 bytes
		setupRtti3_32(builder, 0x01003368L, 0, 0, 1, "0x01003390"); // 16 bytes
		setupRtti2_32(builder, 0x01003390L, new String[] { "0x010033a8" }); // 4 bytes
		setupRtti1_32(builder, 0x010033a8L, "0x01005200", 0, 0, 0xffffffff, 0, 0x40, "0x01003368"); // 28 bytes (? 28 bytes?)
		setupRtti0_32(builder, 0x01005200L, "0x01003280", "0x00000000", ".?AVBase@@"); // 4 + 4 + 11 bytes + 1 align = 20
		setupVfTable_32(builder, 0x010032f0L, "0x01003340",
			new String[] { "0x01001200", "0x01001280" }); // 4 + (2 * 4) bytes = 12
	}

	protected void setupRtti64CompleteFlow(ProgramBuilder builder) throws Exception {

		setupRtti64Base(builder);
		setupRtti64Shape(builder);
		setupRtti64Circle(builder);
		setupInstructions64(builder);
	}

	protected void setupInstructions64(ProgramBuilder builder) throws Exception {
		// instructions
		setupCode64Bytes(builder, "0x101001120");
		setupCode64Instructions(builder, "0x101001140");
		setupCode64Bytes(builder, "0x101001200");
		setupCode64Instructions(builder, "0x101001214");
		setupCode64Bytes(builder, "0x101001230");
		setupCode64Bytes(builder, "0x101001260");
		setupCode64Instructions(builder, "0x101001280");
		setupCode64Bytes(builder, "0x1010012a0");
	}

	protected void setupRtti64Circle(ProgramBuilder builder) throws Exception {
		// ---- Circle ----
		// rtti4:  10100324c - 10100325f
		// rtti3:  101003268 - 101003277
		// rtti2:  101003290 - 10100329b
		// rtti1:  1010032a8 - 1010032c3
		// rtti0:  1010033e0 - 1010033ff
		// vfTbl:  1010031d0 - 1010032ef
		//
		setupRtti4_64(builder, 0x10100324cL, 0, 0, 0, "0x1010053e0", "0x101003268"); // 20 bytes
		setupRtti3_64(builder, 0x101003268L, 0, 0, 3, "0x101003290"); // 16 bytes
		setupRtti2_64(builder, 0x101003290L,
			new String[] { "0x1010032a8", "0x1010033c4", "0x1010033a8" }); // 12 bytes
		setupRtti1_64(builder, 0x1010032a8L, "0x1010053e0", 0, 0, 0xffffffff, 0, 0x40,
			"0x101003268"); // 28 bytes
		setupRtti0_64(builder, 0x1010053e0L, "0x101003280", "0x00000000", ".?AVCircle@@"); // 8 + 8 + 13 bytes + 3 align = 32
		setupVfTable_64(builder, 0x1010031d0L, "0x10100324c",
			new String[] { "0x101001260", "0x1010012a0", "0x101001120" }); // 8 + (3 * 8) bytes = 32
	}

	protected void setupRtti64Shape(ProgramBuilder builder) throws Exception {
		// ---- Shape ----
		//
		// rtti4:  101003354 - 101003367
		// rtti3:  101003378 - 101003387
		// rtti2:  101003394 - 10100339b
		// rtti1:  1010033c4 - 1010033df
		// rtti0:  101003220 - 10100323b // 8 byte aligned
		// vfTbl:  1010031b0 - 1010031cf // 8 byte aligned
		//
		setupRtti4_64(builder, 0x101003354L, 0, 0, 0, "0x101005220", "0x101003378"); // 20 bytes
		setupRtti3_64(builder, 0x101003378L, 0, 0, 2, "0x101003394"); // 16 bytes
		setupRtti2_64(builder, 0x101003394L, new String[] { "0x1010033c4", "0x1010033a8" }); // 8 bytes
		setupRtti1_64(builder, 0x1010033c4L, "0x101005220", 0, 0, 0xffffffff, 0, 0x40,
			"0x101003378"); // 28 bytes
		setupRtti0_64(builder, 0x101005220L, "0x101003280", "0x00000000", ".?AVShape@@"); // 8 + 8 + 12 bytes + 0 align = 28
		setupVfTable_64(builder, 0x1010031b0L, "0x101003354",
			new String[] { "0x101001214", "0x101001230" }); // 8 + (2 * 8) bytes = 24
	}

	protected void setupRtti64Base(ProgramBuilder builder) throws Exception {
		// ---- Base ----
		// rtti4:  101003340 - 101003353
		// rtti3:  101003368 - 101003377
		// rtti2:  101003390 - 101003393
		// rtti1:  1010033a8 - 1010033c3
		// rtti0:  101003200 - 10100321b
		// vfTbl:  1010032f0 - 101003307
		//
		setupRtti4_64(builder, 0x101003340L, 0, 0, 0, "0x101005200", "0x101003368"); // 20 bytes
		setupRtti3_64(builder, 0x101003368L, 0, 0, 1, "0x101003390"); // 16 bytes
		setupRtti2_64(builder, 0x101003390L, new String[] { "0x1010033a8" }); // 4 bytes
		setupRtti1_64(builder, 0x1010033a8L, "0x101005200", 0, 0, 0xffffffff, 0, 0x40,
			"0x101003368"); // 28 bytes (? 28 bytes?)
		setupRtti0_64(builder, 0x101005200L, "0x101003280", "0x00000000", ".?AVBase@@"); // 8 + 8 + 11 bytes + 1 align = 28
		setupVfTable_64(builder, 0x1010032f0L, "0x101003340",
			new String[] { "0x101001200", "0x101001280" }); // 8 + (2 * 8) bytes = 24
	}

	protected void checkRtti4Data(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "RTTICompleteObjectLocator", new String[] {
			"signature", "offset", "cdOffset", "pTypeDescriptor", "pClassDescriptor" }, 20);
	}

	protected void checkRtti3Data(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "RTTIClassHierarchyDescriptor",
			new String[] { "signature", "attributes", "numBaseClasses", "pBaseClassArray" }, 16);
	}

	protected void checkRtti2Data(ProgramDB program, long address, int numEntries) {
		DataType expectedDataType =
			MSDataTypeUtils.is64Bit(program) ? new ImageBaseOffset32DataType()
					: new PointerDataType(Rtti1Model.getDataType(program),
						program.getDataTypeManager());
		checkArrayData(program, address, expectedDataType, numEntries);
	}

	protected void checkRtti1Data(ProgramDB program, long address) {
		CheckTypeDefOnStructureData(program, address, "RTTIBaseClassDescriptor",
			new String[] { "pTypeDescriptor", "numContainedBases", "where", "attributes",
				"pClassHierarchyDescriptor" },
			28);
		Structure pmdDataType = MSDataTypeUtils.getPMDDataType(program);
	}

	protected void checkVfTableData(ProgramDB program, long metaPointerAddress, long rtti4Address,
			long vfTableAddress, long[] vfAddresses) {
		PointerDataType pointerDataType = new PointerDataType(program.getDataTypeManager());
		checkSimpleData(program, metaPointerAddress, pointerDataType);
		checkSimpleData(program, rtti4Address, Rtti4Model.getDataType(program));
		checkArrayData(program, vfTableAddress, pointerDataType, vfAddresses.length);
		// Check for specific function pointer values?
		Memory memory = program.getMemory();
		AddressSetView loadedAndInitializedAddressSet = memory.getLoadedAndInitializedAddressSet();
		for (long vfAddress : vfAddresses) {
			Address vfAddr = addr(program, vfAddress);
			String failureMessage = "VF Address " + vfAddr +
				" isn't in loaded and initialized memory of program " + program.getName() + ".";
			assertTrue(failureMessage, loadedAndInitializedAddressSet.contains(vfAddr));
		}
	}

}
