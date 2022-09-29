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
package ghidra.framework.main.logviewer.ui;

import java.awt.event.ActionEvent;

import javax.swing.*;

import docking.EmptyBorderToggleButton;
import docking.widgets.EmptyBorderButton;
import generic.theme.GIcon;
import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;

/**
 * Toolbar that contains widgets for controlling the {@link FileViewer}.
 */
public class FVToolBar extends JToolBar {

	private EmptyBorderToggleButton scrollLockButton;
	private EmptyBorderButton fileOpenButton;
	private FVEventListener eventListener;

	/**
	 * Constructor.
	 * @param eventListener the event listener that will be notified of action events
	 */
	public FVToolBar(FVEventListener eventListener) {
		this.eventListener = eventListener;
		createScrollLockTool();
		createFileOpenTool();
	}

	public boolean isScrollLockOn() {
		return scrollLockButton.isSelected();
	}

	public void setScrollLockOn(boolean lock) {
		scrollLockButton.setSelected(lock);
	}

//=================================================================================================
// Private Methods
//=================================================================================================

	private void createFileOpenTool() {
		Action openAction = new FileOpenAction();
		fileOpenButton = new EmptyBorderButton();
		fileOpenButton.setAction(openAction);
		fileOpenButton.setText("Opens the log file folder");
		fileOpenButton.setHideActionText(true);
		add(fileOpenButton);
	}

	private void createScrollLockTool() {
		Action lockAction = new ScrollLockAction();
		scrollLockButton = new EmptyBorderToggleButton();
		scrollLockButton.setAction(lockAction);
		scrollLockButton.setText("Scroll Lock");
		scrollLockButton.setHideActionText(true);
		add(scrollLockButton);
	}

	private class ScrollLockAction extends AbstractAction {

		public ScrollLockAction() {
			super("FVScrollLockAction", new GIcon("icon.version.control.dialog.add"));
			putValue(SHORT_DESCRIPTION, "Scroll Lock");
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			FVEvent tailEvt;
			if (scrollLockButton.isSelected()) {
				tailEvt = new FVEvent(EventType.SCROLL_LOCK_ON, null);
			}
			else {
				tailEvt = new FVEvent(EventType.SCROLL_LOCK_OFF, null);
			}
			eventListener.send(tailEvt);
		}
	}

	private class FileOpenAction extends AbstractAction {

		public FileOpenAction() {
			super("FVFileOpenAction", new GIcon("icon.logviewer.toolbar.file.open"));
			putValue(SHORT_DESCRIPTION, "Opens the log file folder");
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			FVEvent openEvt = new FVEvent(EventType.OPEN_FILE_LOCATION, null);
			eventListener.send(openEvt);
		}
	}
}
