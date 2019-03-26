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

import docking.widgets.fieldpanel.support.FieldUtils;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class OperandLocationDescriptor extends LocationDescriptor {

	OperandLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);
		this.program = program;

		if (location == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null ProgramLocation");
		}

		if (!(location instanceof OperandFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + location);
		}

		OperandFieldLocation operandLocation = (OperandFieldLocation) location;

		homeAddress = operandLocation.getRefAddress();
		label = getLabelForAddress(operandLocation);
	}

	private String getLabelForAddress(OperandFieldLocation location) {

		int operandIndex = location.getOperandIndex();
		ReferenceManager referenceManager = program.getReferenceManager();
		Address address = location.getAddress();
		Reference ref = referenceManager.getReference(address, homeAddress, operandIndex);

		// use the symbol's name where possible
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getSymbol(ref);
		if (symbol != null) {
			return symbol.getName(false);
		}

		// no reference or symbol...this shouldn't happen, but just in case
		return FieldUtils.trimString(location.getOperandRepresentation());
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		//
		// Note: this location assumes that the reference is to the operand itself or to a
		//       variable (see getHomeLocation()).  For the case when operands themselves point
		//       to other things, like structure members, the OperandLocationDescriptor is
		//       not used at all.   (This decision is made in ReferenceUtils).
		//
		ReferenceUtils.getReferences(accumulator, getHomeLocation(), monitor);
	}

	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {

		Address currentAddress = getAddressForHighlightObject(object);
		if (!isInAddresses(currentAddress)) {
			return EMPTY_HIGHLIGHTS;
		}

		if (OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			int offset = text.indexOf(label);
			if (offset >= 0) {
				return new Highlight[] {
					new Highlight(offset, label.length() + offset - 1, highlightColor) };
			}
		}
		else if (LabelFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			if (currentAddress.equals(homeAddress)) {
				int offset = text.indexOf(label);
				if (offset != -1) {
					return new Highlight[] {
						new Highlight(offset, label.length() + offset - 1, highlightColor) };
				}
			}
		}

		return EMPTY_HIGHLIGHTS;
	}
}
