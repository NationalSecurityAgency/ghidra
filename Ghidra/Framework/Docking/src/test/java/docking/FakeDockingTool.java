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
package docking;

import java.awt.Image;
import java.util.List;

import javax.swing.ImageIcon;

import docking.action.DockingActionIf;
import docking.actions.DockingToolActionManager;
import docking.framework.ApplicationInformationDisplayFactory;
import ghidra.framework.options.ToolOptions;

/**
 * A Test Double of the {@link DockingTool} that provides minimal tool functionality, such
 * as the {@link DockingWindowManager}
 */
public class FakeDockingTool extends AbstractDockingTool {

	public FakeDockingTool() {

		DockWinListener listener = new DummyListener();
		List<Image> windowIcons = ApplicationInformationDisplayFactory.getWindowIcons();
		winMgr = new DockingWindowManager("EMPTY", windowIcons, listener, false /*isModal*/,
			true /*isDockable*/, true /*hasStatus*/, null /*DropTargetFactory*/);
		actionMgr = new DockingToolActionManager(this, winMgr);
	}

	@Override
	public String getName() {
		return "Fake Tool";
	}

	@Override
	public ImageIcon getIcon() {
		return null;
	}

	@Override
	public ToolOptions getOptions(String category) {
		ToolOptions opt = optionsMap.get(category);
		if (opt == null) {
			opt = new ToolOptions(category);
			optionsMap.put(category, opt);
		}
		return opt;
	}

	private class DummyListener implements DockWinListener {

		@Override
		public void close() {
			// stub
		}

		@Override
		public List<DockingActionIf> getPopupActions(ActionContext context) {
			return null;
		}

	}

}
