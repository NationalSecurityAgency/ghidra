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
package ghidra.trace.model.breakpoint;

import java.util.Collection;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

@TraceObjectInfo(
	schemaName = "BreakpointLocation",
	shortName = "breakpoint location",
	attributes = {
		TraceObjectBreakpointLocation.KEY_RANGE,
		TraceObjectBreakpointLocation.KEY_EMU_ENABLED,
		TraceObjectBreakpointLocation.KEY_EMU_SLEIGH,
	},
	fixedKeys = {
		TraceObjectBreakpointLocation.KEY_RANGE,
	})
public interface TraceObjectBreakpointLocation extends TraceBreakpoint, TraceObjectInterface {
	String KEY_RANGE = "_range";
	String KEY_EMU_ENABLED = "_emu_enabled";
	String KEY_EMU_SLEIGH = "_emu_sleigh";

	TraceObjectBreakpointSpec getSpecification();

	void setRange(Lifespan lifespan, AddressRange range);

	void setName(Lifespan lifespan, String name);

	void setKinds(Lifespan lifespan, Collection<TraceBreakpointKind> kinds);

	void setEnabled(Lifespan lifespan, boolean enabled);

	void setEmuEnabled(Lifespan lifespan, boolean emuEnabled);

	void setEmuSleigh(Lifespan lifespan, String sleigh);

	void setComment(Lifespan lifespan, String comment);
}
