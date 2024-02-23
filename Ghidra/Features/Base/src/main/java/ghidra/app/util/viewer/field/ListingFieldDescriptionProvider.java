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
package ghidra.app.util.viewer.field;

import docking.widgets.fieldpanel.FieldDescriptionProvider;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

public class ListingFieldDescriptionProvider implements FieldDescriptionProvider {

	@Override
	public String getDescription(FieldLocation loc, Field field) {
		if (field instanceof ListingField listingField) {
			FieldFactory fieldFactory = listingField.getFieldFactory();
			ProgramLocation location = fieldFactory.getProgramLocation(0, 0, listingField);
			Address address = location.getAddress();
			String addressString = address.toString(address.getAddressSpace().showSpaceName(), 1);
			return fieldFactory.getFieldName() + " Field at Address " + addressString;
		}
		return "Unknown Field";
	}
}
