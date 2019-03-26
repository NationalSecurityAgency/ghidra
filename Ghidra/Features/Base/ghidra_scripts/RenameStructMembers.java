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
// Script requests current structure member name and desired new name.
// It then iterates through all structures, renaming the member.
//
// The current name is also replaced by the new name within all structure
// member comments.
//
// Note: Script does not verify that no other member within the structure
//       is already using the new name.
//
//@category CustomerSubmission.Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

import java.util.Iterator;

public class RenameStructMembers extends GhidraScript {

	@Override
	public void run() throws Exception {

		// get current variable name
		String curName = askString("Current member name", "Current Name");
		if (curName == null)
			return;

		// get desired new variable name
		String newName = askString("New member name", "New Name");
		if (newName == null)
			return;

		// initialize counts and get structure iterator
		int memberCount = 0;
		int commentCount = 0;
		Iterator<Structure> structs =
			currentProgram.getListing().getDataTypeManager().getAllStructures();

		// iterate through all structures in current program's listing
		while (structs.hasNext() && !monitor.isCancelled()) {

			// get current structure and list of associated components (members)
			Structure s = structs.next();
			DataTypeComponent[] comps = s.getDefinedComponents();

			// iterate through all components for current structure
			for (int i = 0; i < comps.length; i++) {

				DataTypeComponent dtc = comps[i];

				// rename matching component
				String fieldName = dtc.getFieldName();
				if ((fieldName != null) && (fieldName.equals(curName))) {
					println(s.getName() + "::" + fieldName);
					dtc.setFieldName(newName);
					memberCount = memberCount + 1;
				}

				// replace matching text in component comments
				String comment = dtc.getComment();
				if (comment != null) {
					comment = comment.replaceAll(curName, newName);
					if (!dtc.getComment().equals(comment)) {
						println("comment: " + comment);
						dtc.setComment(comment);
						commentCount = commentCount + 1;
					}
				}
			}
		}

		println("Member name changes:  " + memberCount);
		println("Comment changes:      " + commentCount);
	}
}
