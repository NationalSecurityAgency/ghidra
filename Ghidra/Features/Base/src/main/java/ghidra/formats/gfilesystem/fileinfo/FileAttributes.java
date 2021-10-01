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

import java.util.ArrayList;
import java.util.List;

/**
 * A collection of {@link FileAttribute} values that describe a file. 
 */
public class FileAttributes {
	/**
	 * Read-only empty instance.
	 */
	public static FileAttributes EMPTY = new FileAttributes(List.of());	// read-only because of List.of()

	/**
	 * Creates a {@link FileAttributes} instance containing the specified attribute values.
	 * 
	 * @param attribs var-arg list of {@link FileAttribute} values, null values are ignored and
	 * skipped
	 * @return a new {@link FileAttributes} instance
	 */
	public static FileAttributes of(FileAttribute<?>... attribs) {
		FileAttributes result = new FileAttributes();
		for (FileAttribute<?> fa : attribs) {
			if (fa != null) {
				result.attributes.add(fa);
			}
		}
		return result;
	}

	private List<FileAttribute<?>> attributes;

	/**
	 * Creates a new / empty {@link FileAttributes} instance.
	 */
	public FileAttributes() {
		this.attributes = new ArrayList<>();
	}

	private FileAttributes(List<FileAttribute<?>> attributes) {
		this.attributes = attributes;
	}

	@Override
	public FileAttributes clone() {
		return new FileAttributes(new ArrayList<>(attributes));
	}

	/**
	 * Adds a custom named file attribute.
	 * <p>
	 * The value class should have a reasonable toString() that converts the value to something
	 * that is presentable to the user. 
	 *  
	 * @param name name of the attribute
	 * @param attributeValue value of the attribute
	 */
	public void add(String name, Object attributeValue) {
		add(FileAttributeType.UNKNOWN_ATTRIBUTE, name, attributeValue);
	}

	/**
	 * Adds a typed file attribute value.
	 * <p>
	 * The value class needs to match {@link FileAttributeType#getValueType()}.
	 * 
	 * @param attributeType {@link FileAttributeType} type of this value
	 * @param attributeValue value of attribute
	 */
	public void add(FileAttributeType attributeType, Object attributeValue) {
		add(attributeType, attributeType.getDisplayName(), attributeValue);
	}

	/**
	 * Adds a typed file attribute value.
	 * <p>
	 * The value class needs to match {@link FileAttributeType#getValueType()}.
	 * 
	 * @param attributeType {@link FileAttributeType} type of this value
	 * @param displayName string used to label the value when displayed to the user 
	 * @param attributeValue value of attribute
	 * @throws IllegalArgumentException if attributeValue does not match attributeType's 
	 * {@link FileAttributeType#getValueType()}.
	 */
	public void add(FileAttributeType attributeType, String displayName, Object attributeValue) {
		if (attributeValue != null) {
			attributes.add(FileAttribute.create(attributeType, displayName, attributeValue));
		}
	}

	/**
	 * Gets the value of the specified attribute.
	 * 
	 * @param <T> expected class of the attribute value
	 * @param attributeType {@link FileAttributeType} enum type of attribute to search for
	 * @param valueClass java class of the value
	 * @param defaultValue value to return if attribute is not present
	 * @return value of requested attribute, or defaultValue if not present
	 */
	public <T> T get(FileAttributeType attributeType, Class<T> valueClass, T defaultValue) {
		for (FileAttribute<?> attr : attributes) {
			if (attr.getAttributeType() == attributeType) {
				Object val = attr.getAttributeValue();
				if (valueClass.isAssignableFrom(val.getClass())) {
					return valueClass.cast(val);
				}
				break;
			}
		}
		return defaultValue;
	}

	/**
	 * Return a list of all the attributes added to this instance.
	 *  
	 * @return list of {@link FileAttribute}
	 */
	public List<FileAttribute<?>> getAttributes() {
		return new ArrayList<>(attributes);
	}

	/**
	 * Returns true if the specified attribute is present.
	 * 
	 * @param attributeType attribute to query
	 * @return boolean true if present
	 */
	public boolean contains(FileAttributeType attributeType) {
		for (FileAttribute<?> attr : attributes) {
			if (attr.getAttributeType() == attributeType) {
				return true;
			}
		}
		return false;
	}

}
