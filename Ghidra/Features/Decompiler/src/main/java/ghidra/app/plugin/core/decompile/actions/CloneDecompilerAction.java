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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;

import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class CloneDecompilerAction extends AbstractDecompilerAction {

	public CloneDecompilerAction() {
		super("Decompile Clone");
		ImageIcon image = ResourceManager.loadImage("images/camera-photo.png");
		setToolBarData(new ToolBarData(image, "ZZZ"));
		setDescription("Create a snapshot (disconnected) copy of this Decompiler window ");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarSnapshot"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_T,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return context.getFunction() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		context.getComponentProvider().cloneWindow();
	}
}
