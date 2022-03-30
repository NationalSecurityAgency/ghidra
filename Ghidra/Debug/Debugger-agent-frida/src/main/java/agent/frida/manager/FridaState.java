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
package agent.frida.manager;

import com.sun.jna.NativeLong;

import ghidra.util.Msg;

public enum FridaState {
	
	FRIDA_THREAD_RUNNING("running"),
	FRIDA_THREAD_STOPPED("stopped"),
	FRIDA_THREAD_WAITING("waiting"),
	FRIDA_THREAD_UNINTERRUPTIBLE("uninterruptible"),
	FRIDA_THREAD_HALTED("halted");

	final String str;

	FridaState(String str) {
		this.str = str;
	}

	@Override
	public String toString() {
		return str;
	}
	
	public static FridaState byValue(String val) {
		for (FridaState state : values()) {
			if (state.str.equals(val)) {
				return state;
			}
		}
		Msg.warn(FridaState.class, "No such value: " + val);
		return null;
	}
	
	public static FridaState getState(NativeLong state) {
		return FridaState.values()[state.intValue()];
	}
	
}
