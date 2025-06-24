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

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * The specification of a breakpoint applied to a target object
 * 
 * <p>
 * Note that a single specification could result in several locations, or no locations at all. For
 * example, a breakpoint placed on a function within a module which has not been loaded ("pending"
 * in GDB's nomenclature), will not have any location. On the other hand, a breakpoint expressed by
 * line number in a C++ template or a C macro could resolve to many addresses. The children of this
 * object include the resolved {@link TargetBreakpointLocation}s. If the debugger does not share
 * this same concept, then its breakpoints should implement both the specification and the location;
 * the specification need not have any children.
 * 
 * <p>
 * This object extends {@link TargetTogglable} for a transitional period only. Implementations whose
 * breakpoint specifications can be toggled should declare this interface explicitly. When the
 * specification is user togglable, toggling it should effectively toggle all locations -- whether
 * or not the locations are user togglable.
 * 
 * <p>
 * NOTE: When enumerating trace breakpoints, use the locations, not the specifications.
 */
@TraceObjectInfo(
	schemaName = "BreakpointSpec",
	shortName = "breakpoint specification",
	attributes = {
		TraceObjectBreakpointSpec.KEY_EXPRESSION,
		TraceObjectBreakpointSpec.KEY_KINDS,
		TraceObjectBreakpointSpec.KEY_AS_BPT,
	},
	fixedKeys = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceObjectBreakpointSpec.KEY_EXPRESSION,
		TraceObjectBreakpointSpec.KEY_KINDS,
	})
public interface TraceObjectBreakpointSpec extends TraceBreakpoint, TraceObjectInterface {
	String KEY_EXPRESSION = "_expression";
	String KEY_KINDS = "_kinds";
	String KEY_AS_BPT = "_bpt";

	// TODO: Make hit count part of the common interface?
	// TODO: Make command list part of the common interface?
	// TODO: Make condition part of the common interface?

	Collection<? extends TraceObjectBreakpointLocation> getLocations(long snap);

	String getExpression(long snap);

	void setKinds(Lifespan lifespan, Collection<TraceBreakpointKind> kinds);
}
