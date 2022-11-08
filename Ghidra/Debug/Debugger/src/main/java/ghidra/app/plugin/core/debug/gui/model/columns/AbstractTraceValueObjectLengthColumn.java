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
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.target.TraceObjectValue;

public abstract class AbstractTraceValueObjectLengthColumn
		extends TraceValueObjectPropertyColumn<Long> {

	private final String attributeName;

	public AbstractTraceValueObjectLengthColumn(String attributeName) {
		super(Long.class);
		this.attributeName = attributeName;
	}

	protected Long fromRange(AddressRange range) {
		return range.getLength();
	}

	@Override
	public ValueProperty<Long> getProperty(ValueRow row) {
		return new ValueDerivedProperty<>(row, Long.class) {
			@Override
			public Long getValue() {
				TraceObjectValue entry = row.getAttributeEntry(attributeName);
				if (entry == null || !(entry.getValue() instanceof AddressRange range)) {
					return null;
				}
				return fromRange(range);
			}

			@Override
			public String getDisplay() {
				Long value = getValue();
				return value == null ? "" : ("0x" + Long.toUnsignedString(value, 16));
			}

			@Override
			public String getHtmlDisplay() {
				Long value = getValue();
				return value == null ? ""
						: ("<html><body style='font-family:monospaced'>0x" +
							Long.toUnsignedString(value, 16));
			}
		};
	}
}
