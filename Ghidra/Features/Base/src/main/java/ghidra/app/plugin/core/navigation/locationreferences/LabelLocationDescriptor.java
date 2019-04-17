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

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class LabelLocationDescriptor extends LocationDescriptor {

	LabelLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);

		if (location == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null ProgramLocation");
		}

		if (!(location instanceof LabelFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + location);
		}

		LabelFieldLocation labelLocation = (LabelFieldLocation) location;

		// get the symbol by name
		label = labelLocation.getName();
		homeAddress = labelLocation.getAddress();
	}

	@Override
	public String getTypeName() {
		return label;
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {
		ReferenceUtils.getReferences(accumulator, programLocation, monitor);
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
