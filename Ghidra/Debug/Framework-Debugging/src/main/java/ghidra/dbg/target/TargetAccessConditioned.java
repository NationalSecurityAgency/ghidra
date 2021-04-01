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
 * A target object which may not be accessible
 * 
 * <p>
 * Depending on the state of the debugger, it may not be able to process commands for certain target
 * objects. Objects which may not be accessible should support this interface. Note, that the
 * granularity of accessibility is the entire object, including its children (excluding links). If,
 * e.g., an object can process memory commands but not control commands, it should be separated into
 * two objects.
 */
@DebuggerTargetObjectIface("Access")
public interface TargetAccessConditioned extends TargetObject {
	String ACCESSIBLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "accessible";

	@TargetAttributeType(name = ACCESSIBLE_ATTRIBUTE_NAME, required = true, hidden = true)
	public default boolean isAccessible() {
		return getTypedAttributeNowByName(ACCESSIBLE_ATTRIBUTE_NAME, Boolean.class, true);
	}
}
