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
package help.validator;

import help.validator.model.*;

import java.nio.file.Path;
import java.util.*;

public class AnchorManager {

	private Map<String, AnchorDefinition> anchorsByHelpPath =
		new HashMap<String, AnchorDefinition>();
	private Map<String, AnchorDefinition> anchorsById = new HashMap<String, AnchorDefinition>();
	private Map<String, AnchorDefinition> anchorsByName = new HashMap<String, AnchorDefinition>();
	private Map<String, List<AnchorDefinition>> duplicateAnchorsById =
		new HashMap<String, List<AnchorDefinition>>();

	private List<HREF> anchorRefs = new ArrayList<HREF>();
	private List<IMG> imgRefs = new ArrayList<IMG>();

	public AnchorManager() {
	}

	public void addAnchor(Path file, String anchorName, int srcLineNo) {
		AnchorDefinition anchor = new AnchorDefinition(file, anchorName, srcLineNo);

		String id = anchor.getId();
		if (anchorsById.containsKey(id)) {
			addDuplicateAnchor(anchorName, anchor, id);
			return;
		}

		anchorsById.put(id, anchor);
		anchorsByHelpPath.put(anchor.getHelpPath(), anchor);

		if (anchorName != null) {
			anchorsByName.put(anchorName, anchor);
		}
	}

	private void addDuplicateAnchor(String anchorName, AnchorDefinition anchor, String id) {
		List<AnchorDefinition> list = duplicateAnchorsById.get(id);
		if (list == null) {
			list = new ArrayList<AnchorDefinition>();
			list.add(anchorsById.get(id)); // put in the original definition
			duplicateAnchorsById.put(id, list);
		}

		list.add(anchor); // add the newly found definition

		//		
		// special code: make sure at least one of these duplicates makes it into the map
		// 
		if (anchorName == null) {
			return;
		}

		if (!anchorsByName.containsKey(anchorName)) {
			anchorsByName.put(anchorName, anchor);
			anchorsByHelpPath.put(anchor.getHelpPath(), anchor);
		}
	}

	public Map<String, AnchorDefinition> getAnchorsByHelpPath() {
		return anchorsByHelpPath;
	}

	public AnchorDefinition getAnchorForHelpPath(String path) {
		if (path == null) {
			return null;
		}
		return anchorsByHelpPath.get(path);
	}

	public void addAnchorRef(HREF href) {
		anchorRefs.add(href);
	}

	public void addImageRef(IMG ref) {
		imgRefs.add(ref);
	}

	public List<HREF> getAnchorRefs() {
		return anchorRefs;
	}

	public List<IMG> getImageRefs() {
		return imgRefs;
	}

	public AnchorDefinition getAnchorForName(String anchorName) {
		return anchorsByName.get(anchorName);
	}

	public Map<String, List<AnchorDefinition>> getDuplicateAnchorsByID() {
		cleanupDuplicateAnchors();
		return duplicateAnchorsById;
	}

	private void cleanupDuplicateAnchors() {
		Set<String> keySet = duplicateAnchorsById.keySet();
		for (String id : keySet) {
			List<AnchorDefinition> list = duplicateAnchorsById.get(id);
			for (Iterator<AnchorDefinition> iterator = list.iterator(); iterator.hasNext();) {
				AnchorDefinition anchorDefinition = iterator.next();
				if (anchorDefinition.getLineNumber() < 0) {
					// a line number of < 0 indicates an AnchorDefinition, which is not found in a file
					iterator.remove();
				}
			}

			// if there is only one item left in the list after removing the definitions, then
			// there are not really any duplicate definitions, so cleanup the list
			if (list.size() == 1) {
				list.clear();
				duplicateAnchorsById.remove(id);
			}
		}
	}
}
