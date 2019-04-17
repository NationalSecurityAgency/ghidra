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
package ghidra.program.model.lang;

public class BasicCompilerSpecDescription implements CompilerSpecDescription {
	private final CompilerSpecID id;
	private final String name;

	public BasicCompilerSpecDescription(CompilerSpecID id, String name) {
		this.id = id;
		this.name = name;
	}

	public CompilerSpecID getCompilerSpecID() {
		return id;
	}

	public String getCompilerSpecName() {
		return name;
	}

	public String getSource() {
		return getCompilerSpecID() + " " + getCompilerSpecName();
	}

	@Override
	public String toString() {
		return getCompilerSpecName();
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
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof CompilerSpecDescription))
			return false;
		final CompilerSpecDescription other = (CompilerSpecDescription) obj;
		if (id == null) {
			return other.getCompilerSpecID() == null;
		}
		return id.equals(other.getCompilerSpecID());
	}
}
