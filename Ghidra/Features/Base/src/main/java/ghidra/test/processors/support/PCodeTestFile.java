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
package ghidra.test.processors.support;

import java.io.File;

public class PCodeTestFile {

	public final File file;
	public final String fileReferencePath;

	public PCodeTestFile(File f, String fileReferencePath) {
		this.file = f;
		this.fileReferencePath = fileReferencePath;
	}

	@Override
	public String toString() {
		return fileReferencePath;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((file == null) ? 0 : file.hashCode());
		result = prime * result + ((fileReferencePath == null) ? 0 : fileReferencePath.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PCodeTestFile other = (PCodeTestFile) obj;
		if (file == null) {
			if (other.file != null)
				return false;
		}
		else if (!file.equals(other.file))
			return false;
		if (fileReferencePath == null) {
			if (other.fileReferencePath != null)
				return false;
		}
		else if (!fileReferencePath.equals(other.fileReferencePath))
			return false;
		return true;
	}
}
