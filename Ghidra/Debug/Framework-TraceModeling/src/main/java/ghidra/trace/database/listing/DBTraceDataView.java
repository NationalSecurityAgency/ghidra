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

import java.util.List;

import com.google.common.collect.Range;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.listing.TraceDataView;

public class DBTraceDataView extends
		AbstractComposedDBTraceCodeUnitsView<DBTraceDataAdapter, AbstractSingleDBTraceCodeUnitsView<? extends DBTraceDataAdapter>>
		implements TraceDataView {
	public DBTraceDataView(DBTraceCodeSpace space) {
		super(space, List.of(space.definedData, space.undefinedData));
	}

	@Override
	public boolean coversRange(Range<Long> span, AddressRange range) {
		return !space.instructions.intersectsRange(span, range);
	}

	@Override
	public boolean intersectsRange(Range<Long> span, AddressRange range) {
		return !space.instructions.coversRange(span, range);
	}
}
