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

public class FridaModule {

	private FridaProcess process;
	private String name;
	private String path;
	private String rangeAddress;
	private Long rangeSize;

	public FridaModule(FridaProcess process) {
		this.process = process;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name == null ? "" : name;
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path == null ? "" : path;
	}

	public String getRangeAddress() {
		return rangeAddress;
	}

	public void setRangeAddress(String rangeAddress) {
		this.rangeAddress = rangeAddress == null ? "0" : rangeAddress;
	}

	public Long getRangeSize() {
		return rangeSize;
	}

	public void setRangeSize(Long rangeSize) {
		this.rangeSize = rangeSize;
	}

	public FridaProcess getProcess() {
		return process;
	}

}
