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
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * A marker interface which indicates a thread, usually within a process
 * 
 * <p>
 * This object must be associated with a suitable {@link TargetExecutionStateful}. In most cases,
 * the object should just implement it.
 */
@DebuggerTargetObjectIface("Thread")
public interface TargetThread extends TargetObject {

	String TID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "tid";

	@TargetAttributeType(name = TID_ATTRIBUTE_NAME, hidden = true)
	public default Integer getTid() {
		return getTypedAttributeNowByName(TID_ATTRIBUTE_NAME, Integer.class, null);
	}
}
