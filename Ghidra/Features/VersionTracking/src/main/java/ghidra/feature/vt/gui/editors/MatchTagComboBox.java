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
package ghidra.feature.vt.gui.editors;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.SetMatchTagTask;
import ghidra.util.task.TaskLauncher;

import java.util.*;

import javax.swing.JComponent;

import docking.widgets.combobox.GhidraComboBox;

public class MatchTagComboBox extends GhidraComboBox {

	private final VTSession session;
	private final List<VTMatch> matches;
	private final VTMatchTag initialTag;
	private final JComponent parentComponent;

	public MatchTagComboBox(VTSession session, List<VTMatch> matches,
			JComponent parentComponent, VTMatchTag startTag) {
		this.session = session;
		this.matches = matches;
		this.parentComponent = parentComponent;
		loadTags();
		if (startTag != null) {
			initialTag = startTag;
		}
		else {
			initialTag = (matches != null && matches.size() > 0) ? matches.get(0).getTag() : null;
		}

		VTMatchTag currentTag = initialTag;
		if (currentTag != null) {
			setSelectedItem(currentTag);
		}
		setEditable(false);
	}

	private void loadTags() {
		Set<VTMatchTag> matchTags = session.getMatchTags();
		List<VTMatchTag> tagList = new ArrayList<VTMatchTag>(matchTags);

		Collections.sort(tagList);

		for (VTMatchTag tag : tagList) {
			this.addItem(tag);
		}
	}

	public boolean apply() {
		VTMatchTag tag = (VTMatchTag) getSelectedItem();
		SetMatchTagTask task = new SetMatchTagTask(session, matches, tag);
		new TaskLauncher(task, parentComponent);
		return true;
	}
}
