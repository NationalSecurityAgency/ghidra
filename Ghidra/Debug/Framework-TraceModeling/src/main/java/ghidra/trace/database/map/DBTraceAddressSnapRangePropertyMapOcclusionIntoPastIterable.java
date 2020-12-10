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
package ghidra.trace.database.map;

import com.google.common.collect.Range;

import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

public class DBTraceAddressSnapRangePropertyMapOcclusionIntoPastIterable<T>
		extends AbstractDBTraceAddressSnapRangePropertyMapOcclusionIterable<T> {

	public DBTraceAddressSnapRangePropertyMapOcclusionIntoPastIterable(
			DBTraceAddressSnapRangePropertyMapSpace<T, ?> space, TraceAddressSnapRange within) {
		super(space, within);
	}

	@Override
	protected Rectangle2DDirection getVerticalDirection() {
		return Rectangle2DDirection.TOPMOST;
	}

	@Override
	protected Range<Long> getOcclusionRange(Range<Long> range) {
		long upperEndpoint = DBTraceUtils.upperEndpoint(range);
		if (upperEndpoint == Long.MAX_VALUE) {
			return null;
		}
		return DBTraceUtils.toRange(upperEndpoint + 1, Long.MAX_VALUE);
	}
}
