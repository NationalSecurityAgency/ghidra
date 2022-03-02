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

import com.google.gson.JsonElement;

public class FridaFrame {

	private String address;
	private int frameId;
	private FridaFunction function;

	public FridaFrame(Map<String, JsonElement> map, int n) {
		this.address = map.get("address").getAsString();
		this.frameId = n;		
		this.function = new FridaFunction(map);
	}

	public int getFrameID() {
		return frameId;
	}

	public String getModuleName() {
		return function.getModuleName();
	}

	public String getFunctionName() {
		return function.getFunctionName();
	}

	public String getFileName() {
		return function.getFileName();
	}

	public long getLineNumber() {
		return function.getLineNumber();
	}

	public FridaFunction getFunction() {
		return function;
	}

	public String getAddress() {
		return address;
	}

	public Long getPC() {
		return Long.decode(address);
	}

}
