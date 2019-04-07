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
 * Handles the actions required when the user presses the 'end' key; this moves the viewport
 * to the bottom of the file.
 *
 */
public class EndAction extends AbstractAction {

	private FVEventListener eventListener;

	public EndAction(FVEventListener eventListener) {
		this.eventListener = eventListener;
	}

	@Override
	public void actionPerformed(ActionEvent e) {

		// Now move the viewport down the distance of the viewport.
		FVEvent endEvt = new FVEvent(EventType.SCROLL_END, true);
		eventListener.send(endEvt);
	}
}
