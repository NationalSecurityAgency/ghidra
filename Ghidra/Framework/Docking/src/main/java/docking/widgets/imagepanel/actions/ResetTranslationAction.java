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
package docking.widgets.imagepanel.actions;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.imagepanel.ImagePanel;
import resources.ResourceManager;

/**
 * An action to re-center the image on a NavigableImagePanel.
 */
public class ResetTranslationAction extends ImagePanelDockingAction {

	private static final ImageIcon RECENTER_ICON = ResourceManager.loadImage("images/tag.png");

	public ResetTranslationAction(String owner, ImagePanel imagePanel) {
		super("Recenter", owner, imagePanel);

		setPopupMenuData(new MenuData(new String[] { "Recenter Image" }, "view"));

		setToolBarData(new ToolBarData(RECENTER_ICON));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!super.isEnabledForContext(context)) {
			return false;
		}
		if (imagePanel.getImage() == null) {
			return false;
		}
		return imagePanel.isTranslated();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		imagePanel.resetImageTranslation();
	}
}
