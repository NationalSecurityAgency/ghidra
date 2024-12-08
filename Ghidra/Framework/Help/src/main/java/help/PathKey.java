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
package help;

import java.nio.file.Path;
import java.util.Objects;


/** A class that wraps a Path and allows map lookup for paths from different file systems */
public class PathKey {
	private String path;

	public PathKey(Path p) {
		if (p == null) {
			Objects.requireNonNull(p, "Path cannot be null");
		}
		this.path = p.toString().replace('\\', '/');
	}
	
	public PathKey(String path) {
		Objects.requireNonNull(path, "Path cannot be null");;
		this.path = path.replace('\\', '/');
	}

	@Override
	public int hashCode() {
		return path.hashCode();
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

		PathKey other = (PathKey) obj;

		boolean result = path.equals(other.path);
		return result;
	}

	@Override
	public String toString() {
		return path.toString();
	}
}
