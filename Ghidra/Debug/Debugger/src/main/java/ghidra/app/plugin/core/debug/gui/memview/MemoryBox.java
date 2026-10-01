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
package ghidra.app.plugin.core.debug.gui.memview;

import java.awt.Color;

import ghidra.app.plugin.core.bento.*;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;

public class MemoryBox extends BentoBox {

	protected final Trace trace;
	protected MemviewBoxType type;

	public MemoryBox(Trace trace, String id, MemviewBoxType type, AddressRange range, long tick,
			Color color) {
		super(id, new BoundedObject(tick, Long.MAX_VALUE), new AddressRangeBoundedObject(range),
			color);
		this.trace = trace;
		this.type = type;
	}

	public MemoryBox(Trace trace, String id, MemviewBoxType type, AddressRange range, long tick) {
		this(trace, id, type, range, tick, type.getColor());
	}

	public MemoryBox(Trace trace, String id, MemviewBoxType type, AddressRange range,
			Lifespan span) {
		super(id, new LifespanBoundedObject(span), new AddressRangeBoundedObject(range),
			type.getColor());
		this.trace = trace;
		this.type = type;
	}

	public MemviewBoxType getType() {
		return type;
	}

}
