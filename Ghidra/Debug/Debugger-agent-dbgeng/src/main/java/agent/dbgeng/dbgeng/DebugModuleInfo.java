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
package agent.dbgeng.dbgeng;

/**
 * Information about a module (program or library image).
 * 
 * The fields correspond to the parameters taken by {@code LoadModule} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class DebugModuleInfo {
	public final long imageFileHandle;
	public final long baseOffset;
	public final int moduleSize;
	public final int checkSum;
	public final int timeDateStamp;
	private String moduleName;
	private String imageName;

	public DebugModuleInfo(long imageFileHandle, long baseOffset, int moduleSize, String moduleName,
			String imageName, int checkSum, int timeDateStamp) {
		this.imageFileHandle = imageFileHandle;
		this.baseOffset = baseOffset;
		this.moduleSize = moduleSize;
		this.setModuleName(moduleName);
		this.setImageName(imageName);
		this.checkSum = checkSum;
		this.timeDateStamp = timeDateStamp; // TODO: Convert to DateTime?
	}

	public String toString() {
		return Long.toHexString(baseOffset);
	}

	public String getModuleName() {
		return moduleName;
	}

	public void setModuleName(String moduleName) {
		this.moduleName = moduleName;
	}

	public String getImageName() {
		return imageName;
	}

	public void setImageName(String imageName) {
		this.imageName = imageName;
	}
}
