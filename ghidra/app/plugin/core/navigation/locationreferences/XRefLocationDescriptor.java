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

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.XRefFieldLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class XRefLocationDescriptor extends LocationDescriptor {

	XRefLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);
		this.program = program;

		init();
	}

	protected void init() {
		validate();

		Address xrefAddress = getXRefAddress(programLocation);
		homeAddress = xrefAddress;

		if (homeAddress == null) {
			throw new NullPointerException(
				"Every location descriptor must have a valid home address");
		}

		if (xrefAddress == null) {
			label = getLabelForLocation(programLocation);
			return;
		}

		label = getLabelForLocation(programLocation);
	}

	protected void validate() {
		if (programLocation == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null " + "ProgramLocation");
		}

		if (!(programLocation instanceof XRefFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + programLocation);
		}
	}

	protected Address getXRefAddress(ProgramLocation location) {
		return ((XRefFieldLocation) location).getRefAddress();
	}

	protected String getLabelForLocation(ProgramLocation location) {
		Address refAddress = getXRefAddress(location);
		if (refAddress != null) {
			return refAddress.toString();
		}
		return location.toString();
	}

	/**
	 * Overridden to *not* count the home address as in the list of matching address so that the 
	 * home address will not be considered for highlighting.
	 * @param address The address for which to search.
	 * @return true if the given address is in the set of this location descriptor's 
	 *         reference addresses.
	 */
	@Override
	protected boolean isInAddresses(Address address) {
		return referencesContain(address);
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referencesToIterator = referenceManager.getReferencesTo(homeAddress);
		while (referencesToIterator.hasNext()) {
			accumulator.add(new LocationReference(referencesToIterator.next(), false));
		}
	}

	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {

		Address currentAddress = getAddressForHighlightObject(object);
		if (!isInAddresses(currentAddress)) {
			return EMPTY_HIGHLIGHTS;
		}

		// check each reference looking for a from address from the current address
		Reference[] references = getAllReferencesBetweenAddresses(currentAddress, homeAddress);
		List<Highlight> highlightList = new ArrayList<>();
		for (Reference reference : references) {
			getHighlightsForReference(reference, text, fieldFactoryClass, highlightList,
				highlightColor);
		}

		return highlightList.toArray(new Highlight[highlightList.size()]);
	}

	private void getHighlightsForReference(Reference reference, String text,
			Class<? extends FieldFactory> fieldFactoryClass, List<Highlight> highlightList,
			Color highlightColor) {

		int opIndex = reference.getOperandIndex();
		if (MnemonicFieldFactory.class.isAssignableFrom(fieldFactoryClass) &&
			(opIndex == ReferenceManager.MNEMONIC)) {
			// highlight the mnemonic
			highlightList.add(new Highlight(0, text.length() - 1, highlightColor));
		}
		else if (OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass) &&
			(opIndex > ReferenceManager.MNEMONIC)) {
			// highlight is based upon the stored reference and which operand has the reference
			// use the home address and the current address to get the op index
			String[] parts = text.split(",");
			int offset = text.indexOf(parts[opIndex]);
			int length = parts[opIndex].length() - 1;
			highlightList.add(new Highlight(offset, length, highlightColor));
		}
	}

	private Reference[] getAllReferencesBetweenAddresses(Address fromAddress, Address toAddress) {
		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator references = referenceManager.getReferencesTo(toAddress);

		List<Reference> referenceList = new ArrayList<>();
		while (references.hasNext()) {
			Reference reference = references.next();
			if (reference.getFromAddress().equals(fromAddress)) {
				referenceList.add(reference);
			}
		}

		return referenceList.toArray(new Reference[referenceList.size()]);
	}
}
