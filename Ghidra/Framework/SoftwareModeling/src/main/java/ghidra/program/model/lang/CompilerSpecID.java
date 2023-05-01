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
 * Represents an opinion's compiler (gcc, borlandcpp, etc).
 */
public final class CompilerSpecID implements Comparable<CompilerSpecID> {

	public static final String DEFAULT_ID = "default";

	private final String id;

	/**
	 * Creates a new compiler spec ID.
	 * 
	 * @param id The compiler ID (gcc, borlandcpp, etc) as defined in the appropriate 
	 * {@link LanguageDescription}.  If null the value of "default" will be assumed.
	 */
	public CompilerSpecID(String id) {
		this.id = id != null ? id : DEFAULT_ID;
	}

	/**
	 * Gets the compiler spec ID as a string.
	 * 
	 * @return The compilers spec ID as a string.
	 * @throws IllegalArgumentException if the compiler spec ID is null or empty.
	 */
	public String getIdAsString() {
		return id;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + id.hashCode();
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
		if (!(obj instanceof CompilerSpecID)) {
			return false;
		}
		final CompilerSpecID other = (CompilerSpecID) obj;
		return id.equals(other.id);
	}

	@Override
	public String toString() {
		return id;
	}

	@Override
	public int compareTo(CompilerSpecID o) {
		return id.compareTo(o.id);
	}
}
