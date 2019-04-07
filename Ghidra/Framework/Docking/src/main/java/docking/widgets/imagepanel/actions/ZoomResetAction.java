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
import docking.action.ToolBarData;
import docking.widgets.imagepanel.ImagePanel;
import resources.ResourceManager;

/**
 * An action to reset the zoom of a NavigableImagePanel.
 */
public class ZoomResetAction extends ImagePanelDockingAction {

	private static final ImageIcon ZOOM_ICON = ResourceManager.loadImage("images/zoom.png");

	public ZoomResetAction(String owner, ImagePanel imagePanel) {
		super("Reset Zoom", owner, imagePanel);

		setToolBarData(new ToolBarData(ZOOM_ICON));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!super.isEnabledForContext(context)) {
			return false;
		}
		return imagePanel.getZoomFactor() != imagePanel.getDefaultZoomFactor();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		imagePanel.resetZoom();
	}
}
