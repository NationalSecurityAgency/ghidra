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
import com.sun.jna.Pointer;

public class FridaScript extends FridaPointer {

	private NativeLong signal;

	public FridaScript(Pointer script) {
		super(script);
	}

	public NativeLong getSignal() {
		return signal;
	}

	public void setSignal(NativeLong signal) {
		this.signal = signal;
	}

}
