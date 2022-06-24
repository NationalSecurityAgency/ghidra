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

public class FridaSection {

	private FridaModule module;
	private String protection;
	private String rangeAddress;
	private Long rangeSize;
	private FridaFileSpec fileSpec;

	public FridaSection(FridaModule module) {
		this.module = module;
	}

	public String getProtection() {
		return protection;
	}

	public void setProtection(String protection) {
		this.protection = protection;
	}

	public String getRangeAddress() {
		return rangeAddress;
	}

	public void setRangeAddress(String rangeAddress) {
		this.rangeAddress = rangeAddress;
	}

	public Long getRangeSize() {
		return rangeSize;
	}

	public void setRangeSize(Long rangeSize) {
		this.rangeSize = rangeSize;
	}

	public String getFilePath() {
		return fileSpec.getPath();
	}

	public void setFilePath(String filePath) {
		this.fileSpec = new FridaFileSpec(filePath);
	}

	public Long getFileOffset() {
		return fileSpec.getOffset();
	}

	public void setFileOffset(Long fileOffset) {
		fileSpec.setOffset(fileOffset);
	}

	public Long getFileSize() {
		return fileSpec.getSize();
	}

	public void setFileSize(Long fileSize) {
		fileSpec.setSize(fileSize);
	}

	public Boolean isReadable() {
		return protection.contains("r");
	}

	public Boolean isWritable() {
		return protection.contains("w");
	}

	public Boolean isExecutable() {
		return protection.contains("x");
	}

	public FridaFileSpec getFileSpec() {
		return fileSpec;
	}
	
	public FridaModule getModule() {
		return module;
	}
	
}
