/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.main.datatree;

import java.io.Serializable;

/**
 * Version info that is inside of the VersionInfoTransferable;
 * must be serializable.
 */
public class VersionInfo implements Serializable {

	private String domainFilePath;
	private int versionNumber;
		
	/**
	 * Construct a new version info object. 
	 * @param domainFilePath pathname for the domain file.
	 * @param versionNumber version number
	 */
	VersionInfo(String domainFilePath, int versionNumber) {
		this.domainFilePath = domainFilePath;
		this.versionNumber = versionNumber;
	}
	/**
	 * Get the path to the domain file.
	 */
	public String getDomainFilePath() {
		return domainFilePath;
	}
	/**
	 * Get the version number.
	 */
	public int getVersionNumber() {
		return versionNumber;
	}
		
}
