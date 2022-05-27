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

public class FridaSymbol {

	private FridaModule module;
	private boolean isGlobal;
	private String type;
	private String sectionId;
	private String name;
	private String address;
	private Long size;

	public FridaSymbol(FridaModule module) {
		this.module = module;
	}

	public FridaModule getModule() {
		return module;
	}

	public boolean isGlobal() {
		return isGlobal;
	}

	public void setGlobal(boolean isGlobal) {
		this.isGlobal = isGlobal;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getSectionId() {
		return sectionId;
	}

	public void setSectionId(String section) {
		this.sectionId = section;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public Long getSize() {
		return size;
	}

	public void setSize(Long size) {
		this.size = size;
	}

}
