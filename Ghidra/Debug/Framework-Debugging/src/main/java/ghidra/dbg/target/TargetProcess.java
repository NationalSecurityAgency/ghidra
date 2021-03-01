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
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * A marker interface which indicates a process, usually on a host operating system
 * 
 * <p>
 * If this object does not support {@link TargetExecutionStateful}, then its mere existence in the
 * model implies that it is {@link TargetExecutionState#ALIVE}. TODO: Should allow association via
 * convention to a different {@link TargetExecutionStateful}, but that may have to wait until
 * schemas are introduced.
 */
@DebuggerTargetObjectIface("Process")
public interface TargetProcess extends TargetObject {

	String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";

	@TargetAttributeType(name = PID_ATTRIBUTE_NAME, hidden = true)
	public default Long getPid() {
		return getTypedAttributeNowByName(PID_ATTRIBUTE_NAME, Long.class, null);
	}
}
