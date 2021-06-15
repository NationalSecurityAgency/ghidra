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
import ghidra.program.model.address.Address;

/**
 * One frame (call record) of an execution stack
 */
@DebuggerTargetObjectIface("StackFrame")
public interface TargetStackFrame extends TargetObject {

	String PC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pc";

	/**
	 * Get the program counter for the frame
	 * 
	 * <p>
	 * Note for some platforms, this may differ from the value in the program counter register.
	 * 
	 * @return a future completing with the address of the executing (or next) instruction.
	 */
	@TargetAttributeType(name = PC_ATTRIBUTE_NAME, required = true, hidden = true)
	public default Address getProgramCounter() {
		return getTypedAttributeNowByName(PC_ATTRIBUTE_NAME, Address.class, Address.NO_ADDRESS);
	}
}
