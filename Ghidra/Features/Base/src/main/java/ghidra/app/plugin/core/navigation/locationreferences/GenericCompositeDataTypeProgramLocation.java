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

import java.util.Objects;

import ghidra.app.services.FieldMatcher;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;

/**
 * A class to signal that the ProgramLocation is used for data types and is not really
 * connected to the listing.  This is a subclass is designed for data types that have fields, such
 * as {@link Composite} types and {@link Enum} types.
 *
 * @see GenericCompositeDataTypeLocationDescriptor
 */
public class GenericCompositeDataTypeProgramLocation extends GenericDataTypeProgramLocation {

	private FieldMatcher fieldMatcher;

	GenericCompositeDataTypeProgramLocation(Program program, DataType dataType, String fieldName) {
		this(program, dataType, new FieldMatcher(dataType, fieldName));
	}

	GenericCompositeDataTypeProgramLocation(Program program, DataType dataType,
			FieldMatcher fieldMatcher) {
		super(program, dataType);
		this.fieldMatcher = Objects.requireNonNull(fieldMatcher);

		// sanity check
		if (!Objects.equals(dataType, fieldMatcher.getDataType())) {
			throw new AssertException("Data type does not match the FieldMatcher type");
		}
	}

	public FieldMatcher getFieldMatcher() {
		return fieldMatcher;
	}
}
