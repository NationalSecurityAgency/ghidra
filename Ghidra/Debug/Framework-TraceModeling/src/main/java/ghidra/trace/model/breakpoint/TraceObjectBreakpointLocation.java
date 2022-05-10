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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.annot.TraceObjectInfo;
import ghidra.util.exception.DuplicateNameException;

@TraceObjectInfo(
	targetIf = TargetBreakpointLocation.class,
	shortName = "breakpoint location",
	fixedKeys = {
		TargetObject.DISPLAY_ATTRIBUTE_NAME,
		TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME,
		TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME,
		TraceObjectBreakpointLocation.KEY_COMMENT,
		TraceObjectBreakpointLocation.KEY_RANGE,
	})
public interface TraceObjectBreakpointLocation extends TraceBreakpoint, TraceObjectInterface {
	String KEY_COMMENT = "_comment";
	String KEY_RANGE = "_range"; // Duplicates address,length

	TraceObjectBreakpointSpec getSpecification();

	void setLifespan(Range<Long> lifespan) throws DuplicateNameException;

	void setRange(Range<Long> lifespan, AddressRange range);

	void setName(Range<Long> lifespan, String name);

	void setKinds(Range<Long> lifespan, Collection<TraceBreakpointKind> kinds);

	void setEnabled(Range<Long> lifespan, boolean enabled);

	void setComment(Range<Long> lifespan, String comment);
}
