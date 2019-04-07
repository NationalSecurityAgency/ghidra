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
package ghidra.app.plugin.core.navigation.locationreferences;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import ghidra.app.cmd.function.SetReturnDataTypeCmd;
import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.util.viewer.field.FieldNameFieldFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FieldNameFieldLocation;
import ghidra.program.util.ProgramLocation;

public class LocationReferencesPlugin3Test extends AbstractLocationReferencesTest {

	@Test
	public void testFunctionReturnTypeLocationDescriptor() throws Exception {

		// 0100415a - sscanf
		Address address = addr(0x0100415a);
		int parameterColumn = 1;
		goTo(address, "Function Signature", parameterColumn);

		// change the return type 
		DataType dataType = setReturnTypeToByte(address);

		search();

		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();

		// apply a new datatype and make sure that the provider updates
		Address applyAddress = addr(0x01004152);
		createData(applyAddress, dataType);

		search();

		assertResultCount(
			"Applying a data type at a different location did not increase the reference count.",
			referenceCount + 1);

		clearData(applyAddress);

		assertResultCount("Clearing a data type did not reset the reference count.",
			referenceCount);
	}

	@Test
	public void testFunctionParameterTypeLocationDescriptor() throws Exception {

		// 0100415a - sscanf - string
		Address address = addr(0x0100415a);
		int parameterColumn = 19; // param 0's type
		goTo(address, "Function Signature", parameterColumn);

		search();

		// test that the provider shows the correct number of references
		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();

		// apply a new datatype and make sure that the provider updates
		Variable variable = getVariable(address, 0);
		DataType dataType = variable.getDataType();

		Address applyAddress = addr(0x01004152);
		createData(applyAddress, dataType);

		search();

		referenceAddresses = getResultAddresses();
		assertEquals(
			"Applying a data type at a different location did not increase the reference count.",
			referenceCount + 1, referenceAddresses.size());

		clearData(applyAddress);

		assertResultCount("Clearing a data type did not reset the reference count.",
			referenceCount);
	}

	@Test
	public void testFunctionParameterNameLocationDescriptor() throws Exception {

		// 0100415a - sscanf
		Address address = addr(0x0100415a);
		int parameterColumn = 28; // param 0's name
		goTo(address, "Function Signature", parameterColumn);

		search();

		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();
		int ordinal = 0;
		Variable variable = getVariable(address, ordinal);
		verifyVariableReferenceAddresses(variable, referenceAddresses);

		// add a new reference and make sure the provider updates
		Address fromAddress = addr(0x0100415b);
		addVariableReference(fromAddress, variable, 0);

		search();

		referenceAddresses = getResultAddresses();
		assertEquals("Adding a reference did not increase the reference count.",
			referenceAddresses.size(), referenceCount + 1);
		verifyVariableReferenceAddresses(variable, referenceAddresses);

		// remove a reference and make sure the provider updates
		removeReferenceToVariable(variable, fromAddress);

		referenceAddresses = getResultAddresses();
		assertEquals("Removing a reference did not decrease the reference count.", referenceCount,
			referenceAddresses.size());
		verifyVariableReferenceAddresses(variable, referenceAddresses);
	}

	@Test
	public void testFunctionSignatureFieldLocationDescriptor() throws Exception {

		// 0100415a - sscanf
		Address address = addr(0x0100415a);
		int parameterColumn = 11;
		goTo(address, "Function Signature", parameterColumn);

		search();

		// test that the provider shows the correct number of references
		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();
		verifyReferenceAddresses(address, referenceAddresses);

		// add a new reference and make sure the provider updates
		Address fromAddress = addr(0x01003a04);
		createReference(fromAddress, address);

		search();

		referenceAddresses = getResultAddresses();
		assertEquals("Adding a reference did not increase the reference count.",
			referenceAddresses.size(), referenceCount + 1);
		verifyReferenceAddresses(address, referenceAddresses);

		// remove a reference and make sure the provider updates
		removeReferenceToAddress(address, fromAddress);

		referenceAddresses = getResultAddresses();
		assertEquals("Removing a reference did not decrease the reference count.", referenceCount,
			referenceAddresses.size());
		verifyReferenceAddresses(address, referenceAddresses);
	}

	@Test
	public void testLabelLocationDescriptor() throws Exception {

		// 010039fe - LAB_010039fe 
		Address address = addr(0x010039fe);
		int column = 3;
		goTo(address, "Label", column);

		search();

		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();
		verifyReferenceAddresses(address, referenceAddresses);

		// add a new reference and make sure the provider updates
		Address fromAddress = addr(0x01003a04);
		createReference(fromAddress, address);

		search();

		referenceAddresses = getResultAddresses();
		assertEquals("Adding a reference did not increase the reference count.",
			referenceAddresses.size(), referenceCount + 1);
		verifyReferenceAddresses(address, referenceAddresses);

		// remove a reference and make sure the provider updates
		removeReferenceToAddress(address, fromAddress);

		referenceAddresses = getResultAddresses();
		assertEquals("Removing a reference did not decrease the reference count.", referenceCount,
			referenceAddresses.size());
		verifyReferenceAddresses(address, referenceAddresses);
	}

	@Test
	public void testFieldNameLocationDescriptor_ArrayIndex() throws Exception {

		openData(0x01005500);

		goTo(addr(0x01005500), FieldNameFieldFactory.FIELD_NAME, 1);

		ProgramLocation location = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = ReferenceUtils.getLocationDescriptor(location);
		assertThat(descriptor, is(instanceOf(AddressLocationDescriptor.class)));
	}

	@Test
	public void testFieldNameLocationDescriptor_ArrayIndex_InsideStructure() throws Exception {

		openData(0x01005540);

		goTo(addr(0x01005545), FieldNameFieldFactory.FIELD_NAME, 1);

		ProgramLocation location = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = ReferenceUtils.getLocationDescriptor(location);
		assertThat(descriptor, is(instanceOf(AddressLocationDescriptor.class)));
	}

	@Test
	public void testFieldNameLocationDescriptor_StructureFieldName_ArrayInStructure()
			throws Exception {

		openData(0x01005540);

		goTo(addr(0x01005541), FieldNameFieldFactory.FIELD_NAME, 1);

		ProgramLocation location = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = ReferenceUtils.getLocationDescriptor(location);
		assertThat(descriptor, is(instanceOf(StructureMemberLocationDescriptor.class)));
	}

	@Test
	public void testFieldNameLocationDescriptor_StructureInArray() throws Exception {

		openData(0x01005520);

		int[] path = new int[] { 1, 0 }; // from the parent: array element 1, field member 0
		FieldNameFieldLocation fieldLocation =
			new FieldNameFieldLocation(program, addr(0x01005525), path, "my_int", 1);
		goTo(fieldLocation);

		ProgramLocation location = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = ReferenceUtils.getLocationDescriptor(location);
		assertThat(descriptor, is(instanceOf(StructureMemberLocationDescriptor.class)));
	}

	@Test
	public void testFindReferencesToFunctionDefinitionDataTypeFromService() throws Exception {
		// 
		// For this test we will have to create a FunctionDefinitionData type that matches
		// that of an existing function
		//

		// 01002cf5 - ghidra
		FunctionManager functionManager = program.getFunctionManager();
		Function ghidraFunction = functionManager.getFunctionAt(addr(0x01002cf5));

		FunctionDefinitionDataType definition =
			new FunctionDefinitionDataType(ghidraFunction, false);

		runSwing(() -> locationReferencesPlugin.findAndDisplayAppliedDataTypeAddresses(definition));

		assertHasResults("Could not find references using a FunctionDefinition data type");
	}

	@Test
	public void testDataTypeSearchDoesntHaveDuplicateMatches_SCR_8901() throws Exception {
		//
		// The same address should not appear in the results when searching for all uses of
		// a data type.
		//

		// create some bytes
		createByte(0x010013d9);
		createByte(0x010013dd);
		createByte(0x010013e7);

		// put the cursor on that byte
		Address address = addr(0x010013d9);
		goTo(address, "Mnemonic");

		// search
		search();

		// validate no dupes in results
		List<LocationReference> references = getResultLocations();
		assertTrue("Expected multiple applies locations for data type", references.size() > 2);

		HashSet<LocationReference> asSet = new HashSet<>(references);
		if (asSet.size() < references.size()) {
			fail("Found duplicate entries in location references! Values: " + references);
		}
	}

	@Test
	public void testDyamicData_AddressField() throws Exception {

		//
		// Dynamic data types should show all references to the the outermost data, including
		// offcut.  
		//

		// go to an unused address
		String addressString = "0x010054e8";
		createString_CallStructure(addressString); 		// "call_structure_A: %s\n",00

		Address stringAddr = addr(addressString);
		Address start = stringAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, start);

		Address offcut1 = start.add(1);
		Address from2 = addr(0x01005301);
		createReference(from2, offcut1);

		Address offcut2 = start.add(2);
		Address from3 = addr(0x01005302);
		createReference(from3, offcut2);

		goToDataAddressField(start);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from1, from2, from3);

		goToDataMnemonicField(start);
		search();

		results = getResultLocations();
		// Note: the DT address is included when searching from the mnemonic
		assertContains(results, from1, from2, from3, stringAddr);
	}

	@Test
	public void testDyamicData_MnemonicField() throws Exception {

		//
		// Dynamic data types should show all references to the the outermost data, including
		// offcut.  Also, since we are searching from the mnemonic, we find all data references.
		//

		// go to an unused address
		String addressString = "0x010054e8";
		createString_CallStructure(addressString); 		// "call_structure_A: %s\n",00

		Address stringAddr = addr(addressString);
		Address start = stringAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, start);

		Address offcut1 = start.add(1);
		Address from2 = addr(0x01005301);
		createReference(from2, offcut1);

		Address offcut2 = start.add(2);
		Address from3 = addr(0x01005302);
		createReference(from3, offcut2);

		goToDataMnemonicField(start);
		search();

		List<LocationReference> results = getResultLocations();
		// Note: the DT address is included when searching from the mnemonic
		assertContains(results, from1, from2, from3, stringAddr);
	}

	

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void createString_CallStructure(String addressString) throws Exception {
		// String
		// "call_structure_A: %s\n",00

		String s = "63 61 6c 6c 5f 73 74 72 75 63 74 75 72 65 5f 41 3a 20 25 73 0a 00";
		// go to an unused address
		builder.setBytes(addressString, s);

		Address stringAddr = addr(addressString);
		goTo(stringAddr);
		createData(stringAddr, new TerminatedStringDataType());
	}

	private Reference addVariableReference(Address fromAddress, Variable variable, int opindex) {
		int txId = program.startTransaction("AddVarRef");
		try {
			ReferenceManager refMgr = program.getReferenceManager();
			Reference ref;
			if (variable.isStackVariable()) {
				ref = refMgr.addStackReference(fromAddress, 0, variable.getStackOffset(),
					RefType.DATA, SourceType.USER_DEFINED);
			}
			else {
				ref = refMgr.addMemoryReference(fromAddress, variable.getMinAddress(), RefType.DATA,
					SourceType.USER_DEFINED, 0);
			}
			assertNotNull("Unable to add reference to: " + variable, ref);
			return ref;
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private Variable getVariable(Address address, int ordinal) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(address);
		return function.getParameter(ordinal);
	}

	private DataType setReturnTypeToByte(Address address) {
		DataType byteDataType = getDataType("byte");

		SetReturnDataTypeCmd command =
			new SetReturnDataTypeCmd(address, byteDataType, SourceType.ANALYSIS);
		assertTrue("Unable to set the return type of the function at: " + address,
			applyCmd(program, command));
		return byteDataType;
	}

	private void verifyVariableReferenceAddresses(Variable variable,
			Collection<Address> referenceAddresses) {
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference[] variableRefsTo = referenceManager.getReferencesTo(variable);

		assertEquals(
			"The number of references from the provider does not match the number " +
				"of references found by the LocationDescriptor.",
			variableRefsTo.length, referenceAddresses.size());
		for (Reference element : variableRefsTo) {
			Address fromAddress = element.getFromAddress();
			assertTrue(
				"Found a reference from the reference manager that is different than " +
					"that found by the LocationDescriptor.",
				referenceAddresses.contains(fromAddress));
		}
	}

	private void verifyReferenceAddresses(Address address, Collection<Address> referenceAddresses) {
		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referencesIterator = referenceManager.getReferencesTo(address);

		int i = 0;
		for (; referencesIterator.hasNext(); i++) {
			Reference reference = referencesIterator.next();
			Address fromAddress = reference.getFromAddress();
			assertTrue(
				"Found a reference from the reference manager that is different that " +
					"that found by the LocationDescriptor.",
				referenceAddresses.contains(fromAddress));
		}
		assertEquals("The number of references from the provider does not match the number " +
			"of references found by the LocationDescriptor.", i, referenceAddresses.size());
	}

	private void removeReferenceToVariable(Variable variable, Address fromAddress) {
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference[] variableRefsTo = referenceManager.getReferencesTo(variable);

		Reference reference = null;
		for (Reference element : variableRefsTo) {
			if (element.getFromAddress().equals(fromAddress)) {
				reference = element;
				break;
			}
		}

		RemoveReferenceCmd removeRefCommand = new RemoveReferenceCmd(reference);
		assertTrue("Unable to delete reference to: " + variable.getMinAddress(),
			applyCmd(program, removeRefCommand));
	}

	private void removeReferenceToAddress(Address toAddress, Address fromAddress) {
		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referencesIterator = referenceManager.getReferencesTo(toAddress);

		Reference reference = null;
		for (; referencesIterator.hasNext();) {
			Reference currentReference = referencesIterator.next();
			Address refFromAddress = currentReference.getFromAddress();
			if (refFromAddress.equals(fromAddress)) {
				reference = currentReference;
				break;
			}
		}

		RemoveReferenceCmd removeRefCommand = new RemoveReferenceCmd(reference);
		assertTrue("Unable to delete reference to: " + toAddress,
			applyCmd(program, removeRefCommand));
	}

	private void clearData(Address applyAddress) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(applyAddress);
		ClearCmd clearCommand = new ClearCmd(cu, null);
		assertTrue("Unable to clear data type at address: " + applyAddress,
			applyCmd(program, clearCommand));
	}

}
