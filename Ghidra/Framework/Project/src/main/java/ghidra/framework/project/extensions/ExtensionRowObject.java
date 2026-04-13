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
package ghidra.framework.project.extensions;

import java.util.Objects;
import java.util.Set;

import ghidra.util.classfinder.ClassFileInfo;
import ghidra.util.extensions.ExtensionDetails;

class ExtensionRowObject {

	private ExtensionDetails extension;
	private ExtensionInstallationInfo info;

	ExtensionRowObject(ExtensionDetails extension) {
		this.extension = Objects.requireNonNull(extension);
	}

	ExtensionRowObject(ExtensionDetails extension, ExtensionInstallationInfo info) {
		this(extension);
		this.info = info;
	}

	public ExtensionDetails getExtension() {
		return extension;
	}

	public Set<ClassFileInfo> getClassInfos() {
		if (info == null) {
			return Set.of(); // not installed
		}
		return info.getClassInfos();
	}

	@Override
	public String toString() {
		return extension.toString();
	}

	@Override
	public int hashCode() {
		return Objects.hash(extension);
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
		ExtensionRowObject other = (ExtensionRowObject) obj;
		return Objects.equals(extension, other.extension);
	}

}
