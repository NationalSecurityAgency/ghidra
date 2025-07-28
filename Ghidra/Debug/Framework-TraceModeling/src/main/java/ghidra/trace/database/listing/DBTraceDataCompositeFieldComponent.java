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
package ghidra.trace.database.listing;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;

/**
 * The implementation of a field data component in a {@link DBTrace}
 */
public class DBTraceDataCompositeFieldComponent extends AbstractDBTraceDataComponent {
	protected final DataTypeComponent dtc;

	/**
	 * Create a field
	 * 
	 * @param root the root data unit
	 * @param parent the parent component, possibly the root
	 * @param address the minimum address of this component
	 * @param dtc the data type component, giving the index, data type, and length
	 */
	public DBTraceDataCompositeFieldComponent(DBTraceData root, DBTraceDefinedDataAdapter parent,
			Address address, DataTypeComponent dtc) {
		super(root, parent, dtc.getOrdinal(), address, dtc.getDataType(), dtc.getLength());
		this.dtc = dtc;
	}

	@Override
	public String getFieldName() {
		String fieldName = dtc.getFieldName();
		if (fieldName == null || fieldName.length() == 0) {
			return dtc.getDefaultFieldName();
		}
		return fieldName;
	}

	@Override
	public String getFieldSyntax() {
		return "." + getFieldName();
	}

	@Override
	public AddressRange getRange() {
		// TODO: Cache this?
		return new AddressRangeImpl(getMinAddress(), getMaxAddress());
	}

	@Override
	public TraceAddressSnapRange getBounds() {
		// TODO: Cache this?
		return new ImmutableTraceAddressSnapRange(getMinAddress(), getMaxAddress(), getLifespan());
	}
}
