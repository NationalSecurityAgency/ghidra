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
import ghidra.program.model.data.DataType;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.util.TraceAddressSpace;

public class DBTraceDataArrayElementComponent extends AbstractDBTraceDataComponent {
	public DBTraceDataArrayElementComponent(DBTraceData root, DBTraceDefinedDataAdapter parent,
			int index, Address address, DataType dataType, int length) {
		super(root, parent, index, address, dataType, length);
	}

	@Override
	public TraceAddressSpace getTraceSpace() {
		return parent.getTraceSpace();
	}

	@Override
	public String getFieldName() {
		return "[" + index + "]";
	}

	@Override
	public String getFieldSyntax() {
		return getFieldName();
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
