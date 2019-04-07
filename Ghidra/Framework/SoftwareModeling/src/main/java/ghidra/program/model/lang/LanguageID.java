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
package ghidra.program.model.lang;

/**
 * Represents an opinion's processor language (x86:LE:32:default, 8051:BE:16:default, etc).
 */
public class LanguageID implements Comparable<LanguageID> {

	private final String id;

	/**
	 * Creates a new language ID.
	 * 
	 * @param id The language ID (x86:LE:32:default, 8051:BE:16:default, etc).
	 * @throws IllegalArgumentException if the language ID is null or empty.
	 */
	public LanguageID(String id) {
		if (id == null) {
			throw new IllegalArgumentException("id == null not allowed");
		}
		if ("".equals(id)) {
			throw new IllegalArgumentException("empty id not allowed");
		}
		this.id = id;
	}

	/**
	 * Gets the compiler spec ID as a string.
	 * 
	 * @return The compilers spec ID as a string.
	 * @throws IllegalArgumentException if the compiler spec ID is not null or empty.
	 */
	public String getIdAsString() {
		return id;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof LanguageID)) {
			return false;
		}
		final LanguageID other = (LanguageID) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		}
		else if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return id;
	}

	@Override
	public int compareTo(LanguageID o) {
		return id.compareTo(o.id);
	}
}
