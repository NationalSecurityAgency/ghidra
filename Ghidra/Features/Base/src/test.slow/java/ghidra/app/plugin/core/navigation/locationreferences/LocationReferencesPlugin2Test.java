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

import static org.junit.Assert.*;

import java.util.Collection;
import java.util.List;

import org.junit.Test;

import docking.ActionContext;
import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableLocation;

public class LocationReferencesPlugin2Test extends AbstractLocationReferencesTest {

	@Test
	public void testVariableTypeLocationDescriptor() throws Exception {

		// 0100415a - sscanf  - 
		Address address = addr(0x0100415a);
		assertTrue(codeBrowser.goToField(address, "Variable Type", 1, 0, 1));

		search();

		LocationReferencesProvider provider = getResultsProvider();
		LocationDescriptor locationDescriptor = provider.getLocationDescriptor();
		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();

		ProgramLocation currentLocation = locationDescriptor.getLocation();
		VariableLocation variableLocation = (VariableLocation) currentLocation;
		Variable variable = variableLocation.getVariable();
		DataType dataType = variable.getDataType();

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
	public void testMnemonicLocationDescriptor() throws Exception {

		Address address = addr(0x01004350);
		goTo(address, "Mnemonic", 1);

		assertTrue(!showReferencesAction.isEnabledForContext(
			getCodeViewerProvider().getActionContext(null)));

		LocationReferencesProvider provider = getResultsProvider();
		assertNull("Found a provider for showing references to an undefined mnemonic field.",
			provider);

		DataType dataType = getDataType("dword");
		createData(address, dataType);

		search();

		assertHasResults("Did not find references after applying data type.");
	}

	@Test
	public void testOperandLocationDescriptor() throws Exception {

		// 01004731
		Address address = addr(0x0100446f);
		goTo(address, "Operands", 6);

		search();

		assertHasResults("Did not find references from an operand");
	}

	@Test
	public void testOperandLocationDescriptor_WithPointerToInvalidMemoryLocation()
			throws Exception {

		//
		// This test verifies that we can search for references *to* a location that is not
		// in memory.
		//

		// "0x01004480" cc cc cc cc		
		Address address = addr(0x01004480);
		goTo(address, "Operands", 6);

		search();

		assertHasResults("Did not find references to undefined memory");
	}

	@Test
	public void testUnappliedDataType() throws Exception {
		// 01003b49 - undefined
		Address address = addr(0x01003b49);
		goTo(address, "Mnemonic", 1);

		// test that the current provider contains the correct location descriptor for a
		// given location
		assertTrue(!showReferencesAction.isEnabledForContext(
			getCodeViewerProvider().getActionContext(null)));

		assertNoResults("Found a provider for showing references to an undefined mnemonic field.");
	}

	@Test
	public void testVariableNameLocationDescriptor() throws Exception {

		// 0100415a - sscanf
		Address address = addr(0x0100415a);
		int parameterColumn = 3;
		assertTrue(codeBrowser.goToField(address, "Variable Name", 1, 0, parameterColumn));

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
	public void testXRefLocationDescriptor() throws Exception {

		// 01001004 - ADVAPI32.dll_RegCreateKeyW ... XREF[1,0]:   0100446f
		Address address = addr(0x01001004);
		goTo(address, "XRef");

		search();

		LocationReferencesProvider provider = getResultsProvider();

		LocationDescriptor locationDescriptor = provider.getLocationDescriptor();
		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();
		address = locationDescriptor.getHomeAddress();// the XRef address
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
	public void testNotEnabledOnVariableXRefHeader_10502() throws Exception {
		// 0100415a - sscanf
		Address address = addr(0x0100415a);
		int parameterColumn = 5;
		goTo(address, "Variable XRef Header", parameterColumn);

		ActionContext context = getCodeViewerProvider().getActionContext(null);
		assertFalse(showReferencesAction.isEnabledForContext(context));
	}

	@Test
	public void testVariableXRefLocationDescriptor() throws Exception {

		// 0100415a - sscanf
		Address address = addr(0x0100415a);
		int parameterColumn = 5;
		goTo(address, "Variable XRef", parameterColumn);

		search();

		LocationReferencesProvider provider = getResultsProvider();

		// test that the provider shows the correct number of references
		LocationDescriptor locationDescriptor = provider.getLocationDescriptor();
		List<Address> referenceAddresses = getResultAddresses();
		int referenceCount = referenceAddresses.size();
		address = locationDescriptor.getHomeAddress();// the XRef address
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
	public void testUnionData_AddressField() {

		//
		// Ghidra cannot figure out which member of a union was accesses.   Just show all 
		// references into the Union.
		//

		Address unionAddr = addr(0x010054e8);
		goTo(unionAddr);
		UnionDataType union = new UnionDataType("Union");
		union.add(new DWordDataType(), "one", "comment");
		union.add(new DWordDataType(), "two", "comment");
		union.add(new DWordDataType(), "three", "comment");
		union.add(new DWordDataType(), "four", "comment");

		createData(unionAddr, union);

		//
		// Add some refs offcut and not. 
		//
		Address from1 = addr(0x01005300);
		createReference(from1, unionAddr);

		Address from2 = addr(0x01005301);
		Address offcut1 = unionAddr.add(1);
		createReference(from2, offcut1);

		Address from3 = addr(0x01005302);
		Address offcut2 = unionAddr.add(3);
		createReference(from3, offcut2);

		//
		// All references should be found, regardless of which field of the union was clicked
		//
		goToDataAddressField(unionAddr);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from1, from2, from3);

		goToDataAddressField(unionAddr, 3);
		search();

		results = getResultLocations();
		assertContains(results, from1, from2, from3);
	}

	@Test
	public void testUnionData_FieldNameField() {

		//
		// Ghidra cannot figure out which member of a union was accesses.   Just show all 
		// references into the Union.
		//

		Address unionAddr = addr(0x010054e8);
		goTo(unionAddr);
		UnionDataType union = new UnionDataType("Union");
		union.add(new DWordDataType(), "one", "comment");
		union.add(new DWordDataType(), "two", "comment");
		union.add(new DWordDataType(), "three", "comment");
		union.add(new DWordDataType(), "four", "comment");

		createData(unionAddr, union);

		//
		// Add some refs offcut and not. 
		//
		Address from1 = addr(0x01005300);
		createReference(from1, unionAddr);

		Address from2 = addr(0x01005301);
		Address offcut1 = unionAddr.add(1);
		createReference(from2, offcut1);

		Address from3 = addr(0x01005302);
		Address offcut2 = unionAddr.add(3);
		createReference(from3, offcut2);

		//
		// All references should be found, regardless of which field of the union was clicked
		//
		goToDataNameFieldAt(unionAddr);
		search();

		// Search at the top has all results...
		List<LocationReference> results = getResultLocations();
		assertContains(results, from1, from2, from3, unionAddr);

		goToDataNameFieldAt(offcut2, 3);
		search();

		// Search at a sub-data has all results as well
		results = getResultLocations();
		assertContains(results, from1, from2, from3, unionAddr);

		//
		// Just for giggles, make sure we can find references via the calling instruction
		//
		goTo(from1, OperandFieldFactory.FIELD_NAME);
		search();

		results = getResultLocations();
		assertContains(results, from1, from2, from3, unionAddr);
	}

	@Test
	public void testOperandLocationDescriptor_VariableReference() {

		// 01002cf5 - ghidra
		Address addr = addr("0x01002cf5");
		goTo(addr);

		// 01002d06 ff 75 14        PUSH       [EBP + param_4]
		goToOperandField(addr("0x01002d06"));

		ProgramLocation loc = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = locationReferencesPlugin.getLocationDescriptor(loc);

		List<LocationReference> refs = getReferences(descriptor);
		assertEquals(3, refs.size()); // guilty knowledge
	}

	@Test
	public void testMnemonicLocationDescriptor_Instruction() {
		// 01002cf5 - ghidra
		Address addr = addr("0x01002cf5");
		goTo(addr);

		Address from = addr(0x01005300);
		Address to = addr(0x01002d09);
		createReference(from, to);

		// 01002d09 ff d6           CALL       ESI
		goToMnemonicField(to);

		ProgramLocation loc = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = locationReferencesPlugin.getLocationDescriptor(loc);

		List<LocationReference> refs = getReferences(descriptor);
		assertEquals(1, refs.size());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

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
