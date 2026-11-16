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
package ghidra.app.plugin.core.debug.gui.slice;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.util.HTMLUtilities;

class DataSliceNode extends UnitSliceNode<Data> {
	static String computeValue(Trace trace, Data data, long snap) {
		// TODO: TraceData could have getValue/DefaultValueRepresentation(snap)
		DataType dt = data.getDataType();
		MemBuffer buf = trace.getMemoryManager().getBufferAt(snap, data.getAddress());
		return dt.getRepresentation(buf, data, data.getLength());
	}

	static String computeDisplay(Trace trace, Data data, long snap) {
		return HTMLUtilities.escapeHTML(computeValue(trace, data, snap));
	}

	public DataSliceNode(SliceEdgeType type, Trace trace, Data data, long snap,
			boolean displaySnap, Program image, Address staticPc) {
		super(type, computeValue(trace, data, snap), computeDisplay(trace, data, snap),
			trace, data, snap, displaySnap, image, staticPc);
	}
}
