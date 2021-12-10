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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeTypeGroup.*;

import java.util.Date;

import ghidra.formats.gfilesystem.FSRL;

/**
 * Well known types of file attributes.
 * <p>
 * Uncommon information about a file should be added to the {@link FileAttributes} collection
 * as an {@link #UNKNOWN_ATTRIBUTE} with a custom display name.
 * <p>
 * When adding new attribute types to this enum, add them adjacent to other types of the same 
 * {@link FileAttributeTypeGroup category}.  The enum ordinal controls display ordering.
 */
public enum FileAttributeType {
	FSRL_ATTR("FSRL", GENERAL_INFO, FSRL.class),
	NAME_ATTR("Name", GENERAL_INFO, String.class),
	PATH_ATTR("Path", GENERAL_INFO, String.class),
	FILE_TYPE_ATTR("File type", GENERAL_INFO, FileType.class),
	PROJECT_FILE_ATTR("Project file", GENERAL_INFO, String.class),

	SIZE_ATTR("Size", SIZE_INFO, Long.class),
	COMPRESSED_SIZE_ATTR("Compressed size", SIZE_INFO, Long.class),

	CREATE_DATE_ATTR("Create date", DATE_INFO, Date.class),
	MODIFIED_DATE_ATTR("Last modified date", DATE_INFO, Date.class),
	ACCESSED_DATE_ATTR("Last accessed date", DATE_INFO, Date.class),

	USER_NAME_ATTR("User", OWNERSHIP_INFO, String.class),
	USER_ID_ATTR("UserId", OWNERSHIP_INFO, Long.class),
	GROUP_NAME_ATTR("Group", OWNERSHIP_INFO, String.class),
	GROUP_ID_ATTR("GroupId", OWNERSHIP_INFO, Long.class),

	UNIX_ACL_ATTR("Unix acl", PERMISSION_INFO, Long.class),

	IS_ENCRYPTED_ATTR("Is encrypted?", ENCRYPTION_INFO, Boolean.class),
	HAS_GOOD_PASSWORD_ATTR("Password available?", ENCRYPTION_INFO, Boolean.class),

	SYMLINK_DEST_ATTR("Symbolic link destination", MISC_INFO, String.class),
	COMMENT_ATTR("Comment", MISC_INFO, String.class),

	UNKNOWN_ATTRIBUTE("Other attribute", ADDITIONAL_INFO, Object.class);

	private final String displayName;
	private final FileAttributeTypeGroup group;
	private final Class<?> valueType;

	private FileAttributeType(String displayName, FileAttributeTypeGroup group,
			Class<?> valueType) {
		this.displayName = displayName;
		this.group = group;
		this.valueType = valueType;
	}

	/**
	 * Returns the display name of this attribute type.
	 * 
	 * @return string display name
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Returns the {@link FileAttributeTypeGroup group} this attribute belongs in.
	 * 
	 * @return {@link FileAttributeTypeGroup}
	 */
	public FileAttributeTypeGroup getGroup() {
		return group;
	}

	/**
	 * Returns the class the value should match.
	 * 
	 * @return expected class of the value
	 */
	public Class<?> getValueType() {
		return valueType;
	}
}
