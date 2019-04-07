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

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.AssertException;

/**
 * A LocationDescriptor that is used when the user wants to create a descriptor that describes at
 * data type, but not a real location that contains a data type.  Most LocationDescriptors 
 * describe an exact point in the listing display.  This descriptor is designed to describe a 
 * data type, but does not point to any real position in the display.
 */
public class GenericDataTypeLocationDescriptor extends DataTypeLocationDescriptor {

	GenericDataTypeLocationDescriptor(ProgramLocation location, Program program,
			DataType dataType) {
		super(location, program);
		if (!(location instanceof GenericDataTypeProgramLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + location);
		}

		originalDataType = dataType;
		label = generateLabel();
	}

	// Overridden so that we don't try to use our location (which is a dummy location) to see if 
	// the user has clicked on or inside of a structure.
	@Override
	protected DataType getDataType() {
		if (baseDataType == null) {
			return getBaseDataType();
		}
		return baseDataType;
	}

	// Overridden to signal that this type of location descriptor is not associated with any 
	// place in the program
	@Override
	public ProgramLocation getHomeLocation() {
		return null;
	}

	// implemented to ignore the location being provided, since this is a 'dummy' type class
	@Override
	protected String generateLabel() {
		if (originalDataType == null) {
			return "<pending>"; // must be in our parent constructor 
		}
		return "\"" + originalDataType.getName() + "\" (DataType)";
	}

	@Override
	protected String getDataTypeName() {
		if (originalDataType == null) {
			return "<pending>"; // must be in our parent constructor 
		}
		return originalDataType.getName();
	}

	@Override
	protected DataType getSourceDataType() {
		// this is called from the parent constructor, so use the location and not our field, 
		// as it has not yet been initialized
		return ((GenericDataTypeProgramLocation) getLocation()).getDataType();
	}

	@Override
	protected DataType getBaseDataType() {
		DataType type = ReferenceUtils.getBaseDataType(getSourceDataType());
		return type;
	}

	// Overridden to perform a simple check against data types, since the program locations are
	// dummy locations
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (!(obj instanceof GenericDataTypeLocationDescriptor)) {
			return false;
		}

		GenericDataTypeLocationDescriptor otherDescriptor = (GenericDataTypeLocationDescriptor) obj;
		return getDataType().equals(otherDescriptor.getDataType());
	}
}
