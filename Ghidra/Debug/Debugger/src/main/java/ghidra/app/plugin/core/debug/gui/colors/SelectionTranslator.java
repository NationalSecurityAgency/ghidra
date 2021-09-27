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
package ghidra.app.plugin.core.debug.gui.colors;

import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.program.model.address.*;

public interface SelectionTranslator {
	AddressSetView convertFieldToAddress(FieldSelection fieldSelection);

	FieldSelection convertAddressToField(AddressSetView addresses);

	FieldSelection convertAddressToField(AddressRange range);

	default FieldSelection convertAddressToField(Address address) {
		return convertAddressToField(new AddressRangeImpl(address, address));
	}
}
