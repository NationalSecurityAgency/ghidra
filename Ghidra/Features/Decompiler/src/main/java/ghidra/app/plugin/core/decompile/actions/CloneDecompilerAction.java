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
package ghidra.app.plugin.core.decompile.actions;

import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class CloneDecompilerAction extends DockingAction {

	private final DecompilerProvider provider;
	private DecompilerController controller;

	public CloneDecompilerAction(String owner, DecompilerProvider provider,
			DecompilerController controller) {
		super("Decompile Clone", owner);
		this.provider = provider;
		this.controller = controller;
		ImageIcon image = ResourceManager.loadImage("images/camera-photo.png");
		setToolBarData(new ToolBarData(image, "ZZZ"));
		setDescription("Create a snapshot (disconnected) copy of this Decompiler window ");
		setHelpLocation(new HelpLocation("Snapshots", "Snapshots_Start"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK |
			InputEvent.SHIFT_DOWN_MASK));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		return controller.getFunction() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(),
				context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked", "You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		provider.cloneWindow();
	}
}
