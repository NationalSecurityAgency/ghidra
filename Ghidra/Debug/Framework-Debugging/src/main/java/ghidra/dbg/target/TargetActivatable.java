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
 * An object which can be activated
 * 
 * <p>
 * Activation generally means to become the active, selected or focused object. Subsequent commands
 * to the debugger implicitly apply to this object. For example, if a user activates a thread, then
 * subsequent register read/write commands ought to affect the active thread's context.
 * 
 * <p>
 * This interface is only used by RMI targets. The back end must register a suitable method so that
 * the front end can notify it when the user has activated this object. Generally, a user activates
 * the object by double-clicking it in the appropriate table or tree. If it is <em>not</em> marked
 * with this interface, the UI will ignore the action. If it is, the UI will mark it the active
 * object and invoke the appropriate target method. If this interface is present, but a suitable
 * method is not, an error is logged upon attempted activation.
 * 
 * <p>
 * We cannot just use the presence or absence of a suitable activation method as a proxy for this
 * interface, because the registry is only available when the back end is alive.
 */
@DebuggerTargetObjectIface("Activatable")
public interface TargetActivatable extends TargetObject {
	// No methods
}
