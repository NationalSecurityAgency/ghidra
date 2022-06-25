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

import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.annot.TraceObjectInfo;
import ghidra.util.exception.DuplicateNameException;

/**
 * TODO:
 * 
 * <p>
 * NOTE: When enumerating trace breakpoints, use the locations, not the specifications.
 */
@TraceObjectInfo(
	targetIf = TargetBreakpointSpec.class,
	shortName = "breakpoint specification",
	fixedKeys = {
		TargetObject.DISPLAY_ATTRIBUTE_NAME,
		TargetBreakpointSpec.EXPRESSION_ATTRIBUTE_NAME,
		TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME,
	})
public interface TraceObjectBreakpointSpec extends TraceBreakpoint, TraceObjectInterface {
	void setLifespan(Range<Long> lifespan) throws DuplicateNameException;

	Collection<? extends TraceObjectBreakpointLocation> getLocations();

	void setKinds(Range<Long> lifespan, Collection<TraceBreakpointKind> kinds);
}
