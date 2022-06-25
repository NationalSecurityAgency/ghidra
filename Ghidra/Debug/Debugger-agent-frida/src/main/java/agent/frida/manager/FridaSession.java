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

import java.util.Map;

import com.sun.jna.Pointer;

import agent.frida.frida.FridaEng;

public class FridaSession extends FridaPointer {

	private FridaTarget target;
	private FridaProcess process;
	private Map<String, Object> attributes;

	public FridaSession(Pointer session, FridaProcess process) {
		super(session);
		this.process = process;
	}

	public FridaTarget getTarget() {
		return target;
	}

	public void setTarget(FridaTarget target) {
		this.target = target;
	}

	public FridaProcess getProcess() {
		return process;
	}

	public void setProcess(FridaProcess process) {
		this.process = process;
	}

	public String getAttribute(String key) {
		Object object = attributes.get(key);
		if (object == null) {
			return "N/A";
		}
		return object.toString();
	}
	
	public void setAttributes(Map<String, Object> attributes) {
		this.attributes = attributes;
	}
	
	public FridaError detach() {
		FridaError error = new FridaError();
		FridaEng.detach(this, error);
		return error;
	}

	public FridaError resume() {
		FridaError error = new FridaError();
		FridaEng.resume(this, error);
		return error;
	}

}
