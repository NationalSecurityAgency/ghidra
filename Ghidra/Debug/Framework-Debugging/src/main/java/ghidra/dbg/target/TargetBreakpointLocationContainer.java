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
package ghidra.dbg.target;

import ghidra.dbg.DebuggerTargetObjectIface;

/**
 * A place for breakpoint locations to reside
 * 
 * <p>
 * This is just a marker interface for finding where a target's breakpoints are given. In some
 * models, notably GDB, the locations belong to a global set of specifications. The only way to
 * indicate that a location applies to a target is for it to be a successor of that target, at least
 * by linking. To ease discovery, the breakpoint location container for the target must be a
 * canonical successor of the target. The locations in the container may be canonical or links.
 */
@DebuggerTargetObjectIface("BreakpointLocationContainer")
public interface TargetBreakpointLocationContainer extends TargetObject {
	// Nothing here aside from a marker
}
