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

import ghidra.app.cmd.data.AbstractCreateDataTypeModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public abstract class AbstractCreateRttiDataModel extends AbstractCreateDataTypeModel {

	/**
	 * Constructor for the abstract create RTTI data type model. This constructor assumes 
	 * that only a single data type will be created at the indicated address in the program.
	 * @param program the program where the data type would be created.
	 * @param address the address where the data type would be created.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public AbstractCreateRttiDataModel(Program program, Address address,
			DataValidationOptions validationOptions) {
		super(program, address, validationOptions);
	}

	/**
	 * Constructor for the abstract create RTTI data type model. This constructor expects
	 * to create <code>count</code> number of data types at the indicated address in the program.
	 * If more than one data type is being created, they will be in an array data type.
	 * @param program the program where the data type would be created.
	 * @param count the number of data types to create.
	 * @param address the address where the data type would be created.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public AbstractCreateRttiDataModel(Program program, int count, Address address,
			DataValidationOptions validationOptions) {
		super(program, count, address, validationOptions);
	}

	/**
	 * Determines that when following data references from this data type to referenced data types, 
	 * it will eventually traverse via direct (pointer) references or relative 
	 * (image base offset) references to the RTTI 0 data type at the indicated address.
	 * @param rtti0Address the address of the RTTI 0 to which this data refers directly or 
	 * indirectly through other RTTI types.
	 * @return true if a path can be traversed through referenced RTTI data to get to the RTTI 0. 
	 */
	public abstract boolean refersToRtti0(Address rtti0Address);
}
