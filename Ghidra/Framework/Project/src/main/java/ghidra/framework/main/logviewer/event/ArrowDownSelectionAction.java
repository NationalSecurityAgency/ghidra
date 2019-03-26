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
package ghidra.framework.main.logviewer.event;

import java.awt.event.ActionEvent;

import javax.swing.AbstractAction;

import ghidra.framework.main.logviewer.event.FVEvent.EventType;

/**
 * The down arrow should move the selection down one row. Just fire off an event to tell the
 * viewer to increment the selection, which may involve an adjustment to the viewport.
 */
public class ArrowDownSelectionAction extends AbstractAction {

	private FVEventListener eventListener;

	public ArrowDownSelectionAction(FVEventListener eventListener) {
		this.eventListener = eventListener;
	}

	@Override
	public void actionPerformed(ActionEvent e) {

		// Now fire off an event to tell any subscribers to perform the increment.
		FVEvent incrementEvt = new FVEvent(EventType.INCREMENT_AND_ADD_SELECTION, 1);
		eventListener.send(incrementEvt);
	}
}
