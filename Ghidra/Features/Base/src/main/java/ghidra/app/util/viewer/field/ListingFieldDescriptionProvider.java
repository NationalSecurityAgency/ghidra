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
	private boolean verbose = false;
	@Override
	public String getDescription(FieldLocation loc, Field field) {
		if (!(field instanceof ListingField listingField)) {
			return "No program open";
		}
		FieldFactory fieldFactory = listingField.getFieldFactory();
		StringBuilder buf = new StringBuilder(fieldFactory.getFieldName());
		if (verbose) {
			ProgramLocation location = fieldFactory.getProgramLocation(0, 0, listingField);
			if (location != null) {
				Address address = location.getAddress();
				buf.append(" Field at Address ");
				buf.append(address.toString(address.getAddressSpace().showSpaceName(), 1));
			}
		}
		buf.append(": ");
		buf.append(field.getText());
		return buf.toString();
	}

	public void setVerbose(boolean b) {
		this.verbose = b;
	}
}
