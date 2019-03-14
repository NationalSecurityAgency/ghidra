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
package help.validator;

import help.validator.model.AnchorDefinition;
import help.validator.model.HelpFile;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class DuplicateAnchorCollectionByHelpFile implements DuplicateAnchorCollection,
		Comparable<DuplicateAnchorCollectionByHelpFile> {

	private final HelpFile helpFile;
	private final Map<String, List<AnchorDefinition>> duplicateAnchors;

	DuplicateAnchorCollectionByHelpFile(HelpFile helpFile,
			Map<String, List<AnchorDefinition>> duplicateAnchors) {
		this.helpFile = helpFile;
		this.duplicateAnchors = duplicateAnchors;
	}

	public HelpFile getHelpFile() {
		return helpFile;
	}

	@Override
	public String toString() {
		return "Duplicate anchors for file\n\tfile:    " + helpFile + "\n\tanchor:  " +
			getAnchorsAsString();
	}

	private String getAnchorsAsString() {
		StringBuilder buildy = new StringBuilder();
		for (Entry<String, List<AnchorDefinition>> entry : duplicateAnchors.entrySet()) {
			buildy.append("Generated ID: ").append(entry.getKey()).append('\n');
			List<AnchorDefinition> list = entry.getValue();
			for (AnchorDefinition anchorDefinition : list) {
				buildy.append('\t').append('\t').append(anchorDefinition).append('\n');
			}
		}
		return buildy.toString();
	}

	@Override
	public int compareTo(DuplicateAnchorCollectionByHelpFile o) {
		HelpFile helpFile1 = getHelpFile();
		HelpFile helpFile2 = o.getHelpFile();
		Path file1 = helpFile1.getFile();
		Path file2 = helpFile2.getFile();
		return file1.compareTo(file2);
	}
}
