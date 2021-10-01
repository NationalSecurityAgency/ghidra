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

import java.util.Objects;

/**
 * A (type, type_display_string, value) tuple.
 * 
 * @param <T> type of the value
 */
public class FileAttribute<T> {
	private final FileAttributeType attributeType;
	private final String attributeDisplayName;
	private final T attributeValue;

	/**
	 * Creates a new {@link FileAttribute} instance with an 
	 * {@link FileAttributeType#UNKNOWN_ATTRIBUTE} type and the specified display name.
	 * 
	 * @param <T> type of the value
	 * @param name custom display name for the value
	 * @param attributeValue value (should be .toString()'able)
	 * @return new FileAttribute instance
	 */
	public static <T> FileAttribute<T> create(String name, T attributeValue) {
		return create(FileAttributeType.UNKNOWN_ATTRIBUTE, name, attributeValue);
	}

	/**
	 * Creates a new {@link FileAttribute} instance with the specified type and value.
	 * 
	 * @param <T> type of the value
	 * @param attributeType {@link FileAttributeType} type
	 * @param attributeValue value (should match the 
	 * type specified in {@link FileAttributeType#getValueType()}) 
	 * @return new FileAttribute instance
	 */
	public static <T> FileAttribute<T> create(FileAttributeType attributeType,
			T attributeValue) {
		return create(attributeType, attributeType.getDisplayName(), attributeValue);
	}

	/**
	 * Creates a new {@link FileAttribute} instance with the specified type, display name and
	 * value.
	 * 
	 * @param <T> type of the value
	 * @param attributeType {@link FileAttributeType} type
	 * @param attributeDisplayName display name of the type 
	 * @param attributeValue value (should match the 
	 * type specified in {@link FileAttributeType#getValueType()}) 
	 * @return new FileAttribute instance
	 */
	public static <T> FileAttribute<T> create(FileAttributeType attributeType,
			String attributeDisplayName, T attributeValue) {
		if (!attributeType.getValueType().isInstance(attributeValue)) {
			throw new IllegalArgumentException("FileAttribute type " + attributeType +
				" does not match value: " + attributeValue.getClass());
		}
		return new FileAttribute<>(attributeType, attributeDisplayName, attributeValue);
	}

	private FileAttribute(FileAttributeType attributeType, String attributeDisplayName,
			T attributeValue) {
		this.attributeType = attributeType;
		this.attributeDisplayName = attributeDisplayName;
		this.attributeValue = attributeValue;
	}

	/**
	 * Returns the {@link FileAttributeType} of this instance.
	 * 
	 * @return {@link FileAttributeType}
	 */
	public FileAttributeType getAttributeType() {
		return attributeType;
	}

	/**
	 * Returns the display name of this instance.  This is usually derived from
	 * the {@link FileAttributeType#getDisplayName()}.
	 * 
	 * @return string display name
	 */
	public String getAttributeDisplayName() {
		return attributeDisplayName;
	}

	/**
	 * Return the value.
	 * 
	 * @return value
	 */
	public T getAttributeValue() {
		return attributeValue;
	}

	@Override
	public int hashCode() {
		return Objects.hash(attributeDisplayName, attributeType, attributeValue);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FileAttribute<?> other = (FileAttribute<?>) obj;
		return Objects.equals(attributeDisplayName, other.attributeDisplayName) &&
			attributeType == other.attributeType &&
			Objects.equals(attributeValue, other.attributeValue);
	}
}
