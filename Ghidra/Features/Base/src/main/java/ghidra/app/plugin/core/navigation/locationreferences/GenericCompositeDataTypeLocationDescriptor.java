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

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A data type location descriptor that allows you to represent a location for a member field of
 * a composite.
 */
public class GenericCompositeDataTypeLocationDescriptor extends GenericDataTypeLocationDescriptor {

	private String typeAndFieldName;
	private String fieldName;

	public GenericCompositeDataTypeLocationDescriptor(
			GenericCompositeDataTypeProgramLocation location, Program program) {
		super(location, program, location.getDataType());

		this.fieldName = location.getFieldName();
		this.typeAndFieldName = getDataTypeName() + '.' + fieldName;
		label = generateLabel();
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Composite currentDataType = (Composite) getDataType();
		ReferenceUtils.findDataTypeReferences(accumulator, currentDataType, fieldName, program,
			useDynamicSearching, monitor);
	}

	@Override
	public String getTypeName() {
		return super.getTypeName() + "." + fieldName;
	}

	// implemented to ignore the location being provided, since this is a 'dummy' type class
	@Override
	protected String generateLabel() {
		return "\"" + originalDataType.getName() + "." + fieldName + "\" (DataType)";
	}

	// Overridden to perform a simple check against data types, since the program locations are
	// dummy locations
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (!(obj instanceof GenericCompositeDataTypeLocationDescriptor)) {
			return false;
		}

		GenericCompositeDataTypeLocationDescriptor otherDescriptor =
			(GenericCompositeDataTypeLocationDescriptor) obj;
		return getDataType().equals(otherDescriptor.getDataType()) &&
			fieldName.equals(otherDescriptor.fieldName);
	}

	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {

		Address currentAddress = getAddressForHighlightObject(object);
		if (!isInAddresses(currentAddress)) {
			return EMPTY_HIGHLIGHTS;
		}

		if (MnemonicFieldFactory.class.isAssignableFrom(fieldFactoryClass) &&
			(object instanceof Data)) {

			// Not sure if we should ever highlight the mnemonic.  It would only be for data.
			// But, we are always looking for the field of a type, then mnemonic will only hold
			// the parent's name and not the field's name.
		}
		else if (LabelFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			// It would be nice to highlight the label that points into data structures.  
			// However, the label is on the parent address, which is not in our list of matches
			// when we are offcut.  Further, using the program to lookup each address that 
			// comes in to see if it is our paren't address seems too expensive, as highlighting
			// code is called for every paint operation.
			//
			// We could add the parent match to the list of known addresses and then use that 
			// to lookup in real-time later.  To do this we would need the current list of
			// reference addresses and a new list of parent data addresses.  That seems a bit
			// involved just for highlighting a label.
		}
		else if (OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {

			// Not sure how to get the correct part of the text.  This is a hack for now.
			int offset = StringUtils.indexOfIgnoreCase(text, typeAndFieldName, 0);
			if (offset != -1) {
				return new Highlight[] {
					new Highlight(offset, offset + typeAndFieldName.length() - 1, highlightColor) };
			}
		}
		else if (FieldNameFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {

			if (text.equalsIgnoreCase(fieldName)) {
				return new Highlight[] { new Highlight(0, text.length(), highlightColor) };
			}

			String typeName = getDataTypeName();
			if (text.equalsIgnoreCase(typeName)) {
				return new Highlight[] { new Highlight(0, text.length(), highlightColor) };
			}
		}

		return EMPTY_HIGHLIGHTS;
	}

}
