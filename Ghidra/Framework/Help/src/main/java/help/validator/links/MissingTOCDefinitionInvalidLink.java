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
package help.validator.links;

import help.validator.location.HelpModuleCollection;
import help.validator.model.TOCItemReference;

import java.nio.file.Path;

public class MissingTOCDefinitionInvalidLink implements InvalidLink {

	private final TOCItemReference reference;
	private final HelpModuleCollection help;

	public MissingTOCDefinitionInvalidLink(HelpModuleCollection help, TOCItemReference reference) {
		this.help = help;
		this.reference = reference;
		if (Boolean.parseBoolean(System.getProperty("ghidra.help.failfast"))) {
			throw new RuntimeException(toString());
		}
	}

	@Override
	public int identityHashCode() {
		return System.identityHashCode(reference);
	}

	@Override
	public Path getSourceFile() {
		return reference.getSourceFile();
	}

	@Override
	public int getLineNumber() {
		return reference.getLineNumber();
	}

	@Override
	public int compareTo(InvalidLink other) {
		if (other == null) {
			return 1;
		}

		if (!(other instanceof MissingTOCDefinitionInvalidLink)) {
			return -1; // always put us above other types of Invalid Links
		}

		MissingTOCDefinitionInvalidLink otherLink = (MissingTOCDefinitionInvalidLink) other;
		return reference.compareTo(otherLink.reference);
	}

	@Override
	public String toString() {
		return "Missing TOC definition (<tocdef>) for reference (<tocref>):\n\t" + reference;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((reference == null) ? 0 : reference.hashCode());
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
		if (getClass() != obj.getClass()) {
			return false;
		}

		MissingTOCDefinitionInvalidLink other = (MissingTOCDefinitionInvalidLink) obj;
		if (reference == null) {
			if (other.reference != null) {
				return false;
			}
		}
		else if (!reference.equals(other.reference)) {
			return false;
		}
		return true;
	}

}
