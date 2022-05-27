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

import agent.frida.jna.FridaNative;

public class FridaError {

	public FridaNative.GError.ByReference error;	
	
	public FridaError() {
		error = new FridaNative.GError.ByReference();
	}

	public long getValue() {
		return error.code;
	}
	
	public boolean success() {
		return getValue() == 0L;
	}
	

	public String getDescription() {
		return error.code + ":" +error.message;
	}

	public String toString() {
		return getDescription();
	}

}
