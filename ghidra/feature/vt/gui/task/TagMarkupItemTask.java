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
package ghidra.feature.vt.gui.task;

import java.util.List;

import ghidra.feature.vt.api.main.*;
import ghidra.util.task.TaskMonitor;

public class TagMarkupItemTask extends VtTask {

	protected final List<VTMarkupItem> markupItems;
	protected final VTMarkupItemConsideredStatus tag;

	public TagMarkupItemTask(VTSession session, List<VTMarkupItem> markupItems,
			VTMarkupItemConsideredStatus tag) {
		this(tag.name() + " Markup Items", session, markupItems, tag);
	}

	protected TagMarkupItemTask(String title, VTSession session, List<VTMarkupItem> markupItems,
			VTMarkupItemConsideredStatus tag) {
		super(title, session);
		this.markupItems = markupItems;
		this.tag = tag;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {
		monitor.initialize(markupItems.size());
		for (VTMarkupItem markupItem : markupItems) {
			monitor.checkCanceled();
			markupItem.setConsidered(tag);
			monitor.incrementProgress(1);
		}
		return true;
	}
}
