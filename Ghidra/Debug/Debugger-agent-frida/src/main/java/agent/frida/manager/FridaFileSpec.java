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

public class FridaFileSpec {

	private String path;
	private Long offset;
	private Long size;

	public FridaFileSpec(String path) {
		this.path = path;	
	}
	
	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;	
	}

	public String getFilename() {
		int index = path.lastIndexOf("/");
		return index < 0 ? path : path.substring(index+1);
	}

	public String getDirectory() {
		int index = path.lastIndexOf("/");
		return index < 0 ? path : path.substring(0, index);
	}

	public Long getOffset() {
		return offset;
	}

	public void setOffset(Long offset) {
		this.offset = offset;
	}

	public Long getSize() {
		return size;
	}

	public void setSize(Long size) {
		this.size = size;
	}

}
