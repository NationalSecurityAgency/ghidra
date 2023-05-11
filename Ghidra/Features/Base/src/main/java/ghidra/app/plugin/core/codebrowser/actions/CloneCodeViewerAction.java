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
package ghidra.app.plugin.core.codebrowser.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import generic.theme.GIcon;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.util.HelpLocation;

public class CloneCodeViewerAction extends DockingAction {

	private final CodeViewerProvider provider;

	public CloneCodeViewerAction(String owner, CodeViewerProvider provider) {
		super("Code Viewer Clone", owner);
		this.provider = provider;
		Icon image = new GIcon("icon.provider.clone");
		setToolBarData(new ToolBarData(image, "zzzz"));

		setDescription("Create a snapshot (disconnected) copy of this Listing window ");
		setHelpLocation(new HelpLocation("Snapshots", "Snapshots_Start"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_T,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof ProgramActionContext) {
			ProgramActionContext programContext = (ProgramActionContext) context;
			return programContext.getProgram() != null;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		provider.cloneWindow();
	}
}
