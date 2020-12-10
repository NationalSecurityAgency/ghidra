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
import ghidra.program.model.address.Address;

/**
 * One frame of an execution stack
 */
@DebuggerTargetObjectIface("StackFrame")
public interface TargetStackFrame<T extends TargetStackFrame<T>> extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetStackFrame<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetStackFrame.class;

	String PC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pc";

	/**
	 * Get the program counter for the frame
	 * 
	 * Note for some platforms, this may differ from the value in the program counter register.
	 * 
	 * @return a future completing with the address of the executing (or next) instruction.
	 */
	public default Address getProgramCounter() {
		return getTypedAttributeNowByName(PC_ATTRIBUTE_NAME, Address.class, Address.NO_ADDRESS);
	}
}
