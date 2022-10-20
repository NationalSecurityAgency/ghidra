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

import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.annot.TraceObjectInfo;
import ghidra.util.exception.DuplicateNameException;

@TraceObjectInfo(
	targetIf = TargetBreakpointLocation.class,
	shortName = "breakpoint location",
	fixedKeys = {
		TargetObject.DISPLAY_ATTRIBUTE_NAME,
		TargetBreakpointLocation.RANGE_ATTRIBUTE_NAME,
		TraceObjectBreakpointLocation.KEY_COMMENT,
	})
public interface TraceObjectBreakpointLocation extends TraceBreakpoint, TraceObjectInterface {
	String KEY_COMMENT = "_comment";

	TraceObjectBreakpointSpec getSpecification();

	void setLifespan(Lifespan lifespan) throws DuplicateNameException;

	void setRange(Lifespan lifespan, AddressRange range);

	void setName(Lifespan lifespan, String name);

	void setKinds(Lifespan lifespan, Collection<TraceBreakpointKind> kinds);

	void setEnabled(Lifespan lifespan, boolean enabled);

	void setComment(Lifespan lifespan, String comment);
}
