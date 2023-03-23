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
package ghidra.app.plugin.core.debug.gui.model.columns;

import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.target.TraceObjectValue;

public abstract class AbstractTraceValueObjectAddressColumn
		extends TraceValueObjectPropertyColumn<Address> {
	private final String attributeName;

	public AbstractTraceValueObjectAddressColumn(String attributeName) {
		super(Address.class);
		this.attributeName = attributeName;
	}

	protected abstract Address fromRange(AddressRange range);

	@Override
	public ValueProperty<Address> getProperty(ValueRow row) {
		return new ValueAddressProperty(row) {
			@Override
			public Address getValue() {
				TraceObjectValue entry = row.getAttributeEntry(attributeName);
				if (entry == null || !(entry.getValue() instanceof AddressRange range)) {
					return null;
				}
				return fromRange(range);
			}
		};
	}
}
