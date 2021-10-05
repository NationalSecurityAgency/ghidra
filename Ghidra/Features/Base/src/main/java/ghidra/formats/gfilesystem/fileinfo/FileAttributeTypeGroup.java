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
package ghidra.formats.gfilesystem.fileinfo;

/**
 * Categories of file attributes.
 */
public enum FileAttributeTypeGroup {
	GENERAL_INFO("General"),
	SIZE_INFO("Size Info"),
	DATE_INFO("Date Info"),
	OWNERSHIP_INFO("Ownership Info"),
	PERMISSION_INFO("Permission Info"),
	ENCRYPTION_INFO("Encryption Info"),
	MISC_INFO("Misc"),
	ADDITIONAL_INFO("Addional Info");

	private final String descriptiveName;

	private FileAttributeTypeGroup(String descriptiveName) {
		this.descriptiveName = descriptiveName;
	}

	/**
	 * Returns the descriptive name of the group.
	 * 
	 * @return string descriptive name
	 */
	public String getDescriptiveName() {
		return descriptiveName;
	}

}
