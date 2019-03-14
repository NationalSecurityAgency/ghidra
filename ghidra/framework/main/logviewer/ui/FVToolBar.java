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
import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;
import resources.ResourceManager;

/**
 * Toolbar that contains widgets for controlling the {@link FileViewer}.  Currently there is one
 * widget:
 * 
 *   1. SCROLL LOCK - When selected, this will lock the view so it will not move when new data
 *   				  comes in.
 *
 */
public class FVToolBar extends JToolBar {

	private EmptyBorderToggleButton scrollLockBtn;
	private EmptyBorderButton fileOpenBtn;
	private FVEventListener eventListener;

	/**
	 * Constructor.
	 */
	public FVToolBar(FVEventListener eventListener) {
		this.eventListener = eventListener;
		createScrollLockTool();
		createFileOpenTool();
	}

	public EmptyBorderToggleButton getScrollLockBtn() {
		return scrollLockBtn;
	}

	/*********************************************************************************
	 * PRIVATE METHODS
	 *********************************************************************************/

	private void createFileOpenTool() {
		ImageIcon icon = ResourceManager.loadImage("images/lock.png");
		Action lockAction = new ScrollLockAction("undefined", icon, "Scroll Lock");
		scrollLockBtn = new EmptyBorderToggleButton();
		scrollLockBtn.setAction(lockAction);
		scrollLockBtn.setText("Scroll Lock");
		scrollLockBtn.setHideActionText(true);
		scrollLockBtn.setToolTipText("Scroll Lock");
		add(scrollLockBtn);
	}

	private void createScrollLockTool() {
		ImageIcon icon = ResourceManager.loadImage("images/openSmallFolder.png");
		Action openAction = new FileOpenAction("undefined", icon, "Scroll Lock");
		fileOpenBtn = new EmptyBorderButton();
		fileOpenBtn.setAction(openAction);
		fileOpenBtn.setText("Opens the log file folder");
		fileOpenBtn.setHideActionText(true);
		fileOpenBtn.setToolTipText("Opens the log file folder");
		add(fileOpenBtn);
	}

	private class ScrollLockAction extends AbstractAction {

		public ScrollLockAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			FVEvent tailEvt;
			if (scrollLockBtn.isSelected()) {
				tailEvt = new FVEvent(EventType.SCROLL_LOCK_ON, null);
			}
			else {
				tailEvt = new FVEvent(EventType.SCROLL_LOCK_OFF, null);
			}
			eventListener.send(tailEvt);
		}
	}

	private class FileOpenAction extends AbstractAction {

		public FileOpenAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			FVEvent openEvt = new FVEvent(EventType.OPEN_FILE_LOCATION, null);
			eventListener.send(openEvt);
		}
	}
}
