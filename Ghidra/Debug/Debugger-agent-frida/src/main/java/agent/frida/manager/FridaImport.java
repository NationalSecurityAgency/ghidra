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

public class FridaImport {

	private FridaModule module;
	private String type;
	private String slot = "";
	private String mod;
	private String name = "";
	private String address;

	public FridaImport(FridaModule module) {
		this.module = module;
	}

	public FridaModule getModule() {
		return module;
	}

	public String getSlot() {
		return slot;
	}

	public void setSlot(String slot) {
		this.slot = slot == null ? "" : slot;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type == null ? "" : type;
	}

	public String getMod() {
		return mod;
	}

	public void setMod(String module) {
		this.mod = module == null ? "" : module;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name == null ? "" : name;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address == null ? "" : address;
	}

}
