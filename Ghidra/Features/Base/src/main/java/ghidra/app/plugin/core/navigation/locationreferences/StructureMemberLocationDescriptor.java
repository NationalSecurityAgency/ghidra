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
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class StructureMemberLocationDescriptor extends LocationDescriptor {

	private Data parentData;
	private Address parentAddress;
	private List<Data> dataPathList;
	private String fieldName;

	public StructureMemberLocationDescriptor(ProgramLocation memberLocation, String fieldName,
			Program program) {
		super(memberLocation, program);

		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(memberLocation.getAddress());
		if (codeUnit == null) {
			throw new AssertException(
				"Expected a structure at the given location: " + memberLocation);
		}

		if (!(codeUnit instanceof Data)) {
			throw new AssertException(
				"Expected a structure at the given location: " + memberLocation);
		}

		parentData = (Data) codeUnit;
		parentAddress = parentData.getMinAddress();
		long offset = memberLocation.getAddress().subtract(parentAddress);
		Data lowestLevelData = parentData.getPrimitiveAt((int) offset);
		label = lowestLevelData.getPathName();
		homeAddress = memberLocation.getAddress();
		dataPathList = getDataPath(lowestLevelData);
		this.fieldName = fieldName;
	}

	private List<Data> getDataPath(Data leafData) {
		List<Data> list = new ArrayList<>();

		list.add(leafData);
		Data parent = leafData.getParent();
		while (parent != null) {
			list.add(parent);
			parent = parent.getParent();
		}

		return list;
	}

	@Override
	public String getTypeName() {
		Composite composite = getLowestNonLeafComposite();
		String name = composite.getDisplayName();
		if (fieldName != null) {
			return name + "." + fieldName;
		}
		return name;
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Composite composite = getLowestNonLeafComposite();
		ReferenceUtils.findDataTypeReferences(accumulator, composite, fieldName, program,
			useDynamicSearching, monitor);
	}

	private Composite getLowestNonLeafComposite() {

		// Assumption: in the given data path, the leaf item is the thing we seek, so get it's 
		//             parent.
		int i = 0;
		if (fieldName != null) {
			i = 1;
		}

		for (; i < dataPathList.size(); i++) {
			Data data = dataPathList.get(i);
			DataType dt = data.getDataType();
			if (dt instanceof Composite) {
				return (Composite) dt;
			}
		}

		Msg.error(this,
			"Could not find a Composite inside of a Structure Member location: " + toString());
		return null;
	}

	@Override
	ProgramLocation getHomeLocation() {
		return programLocation; // this is the 'structureLocation' passed in our constructor
	}

	@Override
	// overridden to ensure that all members of the structure member's path are 
	// highlighted
	protected boolean isInAddresses(Address address) {
		if (address == null) {
			return false;
		}
		if (super.isInAddresses(address)) {
			return true;
		}

		return isAddressInDataPath(address);
	}

	private boolean isAddressInDataPath(Address address) {
		if (address == null) {
			return false;
		}
		for (Data component : dataPathList) {
			Address componentAddress = component.getMinAddress();
			if (address.equals(componentAddress)) {
				return true;
			}
		}

		return false;
	}

	private Data getFieldData(Address address, String fieldNameText) {
		for (Data component : dataPathList) {
			Address componentAddress = component.getMinAddress();
			if (address.equals(componentAddress)) {
				String name = component.getFieldName();
				if (fieldNameText.equals(name)) {
					return component;
				}
			}
		}
		return null;
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
			if (currentAddress.equals(parentAddress)) {
				String representation = parentData.toString().trim();
				int offset = text.indexOf(representation);
				if (offset != -1) { // make sure this is the parent structure name
					return new Highlight[] {
						new Highlight(offset, label.length() + offset - 1, highlightColor) };
				}
			}
		}
		else if (OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {

			int offset = text.indexOf(label);
			if (offset != -1) {
				return new Highlight[] {
					new Highlight(offset, offset + label.length() - 1, highlightColor) };
			}
		}
		else if (FieldNameFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			Data data = getFieldData(currentAddress, text);
			if (data != null) {
				return new Highlight[] { new Highlight(0, text.length(), highlightColor) };
			}
		}

		return EMPTY_HIGHLIGHTS;
	}
}
