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

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.imagepanel.ImagePanel;
import generic.theme.GIcon;

/**
 * An action to de-zoom the image on a NavigableImagePanel.
 */
public class ZoomOutAction extends ImagePanelDockingAction {

	private static final Icon ZOOM_OUT_ICON = new GIcon("icon.widget.imagepanel.zoom.out");

	public ZoomOutAction(String owner, ImagePanel imagePanel) {
		super("Zoom Out", owner, imagePanel);

		setPopupMenuData(new MenuData(new String[] { "Zoom out" }, "view"));

		setToolBarData(new ToolBarData(ZOOM_OUT_ICON));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!super.isEnabledForContext(context)) {
			return false;
		}
		return imagePanel.canZoomOut();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		imagePanel.zoomOut();
	}
}
