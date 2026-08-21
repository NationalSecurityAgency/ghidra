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
package ghidra.app.util.sourcelanguage;

import java.util.Objects;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * Represents a {@link SourceLanguage source language}'s ID
 */
public class SourceLanguageID implements Comparable<SourceLanguageID> {

	private static final Pattern VALID_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+$");

	private final String id;

	/**
	 * Creates a new {@link SourceLanguageID}.
	 * <p>
	 * An ID must not be blank or contain commas.
	 * 
	 * @param id The {@link SourceLanguage}'s ID
	 * @throws IllegalArgumentException if the ID blank, null, or contains commas
	 */
	public SourceLanguageID(String id) {
		if (StringUtils.isBlank(id)) {
			throw new IllegalArgumentException("Source language 'id' cannot be null or blank");
		}
		if (!VALID_ID_PATTERN.matcher(id).matches()) {
			throw new IllegalArgumentException(
				"Source language 'id' does not match regex: " + VALID_ID_PATTERN);
		}
		this.id = id;
	}

	/**
	 * {@return the {@link SourceLanguage} ID as a string}
	 */
	public String getIdAsString() {
		return id;
	}

	@Override
	public String toString() {
		return id;
	}

	@Override
	public int compareTo(SourceLanguageID o) {
		return id.compareTo(o.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SourceLanguageID other)) {
			return false;
		}
		return Objects.equals(id, other.id);
	}
}
