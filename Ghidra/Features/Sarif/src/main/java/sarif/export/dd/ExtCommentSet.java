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
package sarif.export.dd;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.data.ISF.IsfSetting;
import ghidra.program.model.listing.Data;
import sarif.managers.CommentsSarifMgr;

public class ExtCommentSet implements IsfObject {

	List<ExtComment> comment;
	List<IsfSetting> setting;
	Map<Integer, ExtCommentSet> embedded;

	public ExtCommentSet(Data data) {
		exportComments(data);
		int n = data.getNumComponents();
		if (n > 0) {
			for (int i = 0; i < n; i++) {
				Data component = data.getComponent(i);
				ExtCommentSet cs = new ExtCommentSet(component);
				if (cs.comment != null || cs.setting != null || cs.embedded != null) {
					if (embedded == null) {
						embedded = new HashMap<>();
					}
					embedded.put(i, cs);
				}
			}
		}
	}

	private void exportComments(Data data) {
		for (int i = 0; i < CommentsSarifMgr.COMMENT_TYPES.length; i++) {
			int type = CommentsSarifMgr.COMMENT_TYPES[i];
			String cval = data.getComment(type);
			if (cval != null) {
				if (comment == null) {
					comment = new ArrayList<>();
				}
				ExtComment isf = new ExtComment(data, type);
				comment.add(isf);
			}
		}
		for (String n : data.getNames()) {
			Object value = data.getValue(n);
			if (value != null) {
				if (setting == null) {
					setting = new ArrayList<>();
				}
				IsfSetting isf = new IsfSetting(n, value);
				setting.add(isf);
			}
		}
	}

}
