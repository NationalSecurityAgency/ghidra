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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.*;
import docking.menu.MultiActionDockingAction;
import docking.menu.MultipleActionDockingToolbarButton;
import ghidra.app.plugin.core.functiongraph.FGColorProvider;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.*;

public class SetVertexMostRecentColorAction extends MultiActionDockingAction {

	private final FGController controller;
	private final FGVertex vertex;

	private Icon colorIcon;
	private DockingAction chooseColorAction;
	private DockingAction clearColorAction;

	SetVertexMostRecentColorAction(final FGController controller, FGVertex vertex) {
		super("Set Graph Vertex Color", FunctionGraphPlugin.class.getName());
		this.controller = controller;
		this.vertex = vertex;
		setDescription("Set this block's background color");
		colorIcon = new ColorIcon3D(new Color(189, 221, 252), 12, 12) {
			@Override
			public Color getColor() {
				return controller.getMostRecentColor();
			}
		};

		Icon blankIcon = new EmptyIcon(16, 16);

		MultiIcon multiIcon = new MultiIcon(blankIcon);
		ImageIcon paintBrushImage = ResourceManager.loadImage("images/paintbrush.png");
		ImageIcon scaledBrush = ResourceManager.getScaledIcon(paintBrushImage, 16, 16);

		Point point = getLowerLeftIconOffset(blankIcon, colorIcon);
		Icon translateIcon = new TranslateIcon(colorIcon, point.x, point.y);
		multiIcon.addIcon(translateIcon);

		point = getRightIconOffset(blankIcon, scaledBrush);
		translateIcon = new TranslateIcon(scaledBrush, point.x, point.y);
		multiIcon.addIcon(translateIcon);

		colorIcon = multiIcon;

		setToolBarData(new ToolBarData(colorIcon));

		createActions();
	}

	Icon getToolbarIcon() {
		return colorIcon;
	}

	private void createActions() {
		chooseColorAction =
			new DockingAction("Set Vertex Color", FunctionGraphPlugin.class.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					FGColorProvider colorProvider = controller.getColorProvider();
					Color oldColor = vertex.getBackgroundColor();
					Color newColor = colorProvider.getColorFromUser(oldColor);

					if (newColor == null) {
						return; // cancelled
					}
					if (oldColor.equals(newColor)) {
						return; // same color
					}

					colorProvider.setVertexColor(vertex, newColor);
				}
			};
		ImageIcon imageIcon = ResourceManager.loadImage("images/palette.png");
		chooseColorAction.setMenuBarData(
			new MenuData(new String[] { "Choose New Color" }, imageIcon));
		chooseColorAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Color"));

		clearColorAction =
			new DockingAction("Clear Vertex Color", FunctionGraphPlugin.class.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					FGColorProvider colorProvider = controller.getColorProvider();
					colorProvider.clearVertexColor(vertex);
				}
			};
		clearColorAction.setMenuBarData(new MenuData(new String[] { "Clear Background Color" }));
		clearColorAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Color"));
	}

	@Override
	public void dispose() {
		super.dispose();
		chooseColorAction.dispose();
		clearColorAction.dispose();
	}

	private Point getLowerLeftIconOffset(Icon primaryIcon, Icon overlayIcon) {
		int primaryHeight = primaryIcon.getIconHeight();

		int overlayHeight = overlayIcon.getIconHeight();

		return new Point(0, primaryHeight - overlayHeight);
	}

	private Point getRightIconOffset(Icon primaryIcon, Icon overlayIcon) {
		int primaryWidth = primaryIcon.getIconWidth();

		int overlayWidth = overlayIcon.getIconWidth();

		return new Point(primaryWidth - overlayWidth, 0);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		FGColorProvider colorProvider = controller.getColorProvider();
		colorProvider.setVertexColor(vertex, colorProvider.getMostRecentColor());
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		List<DockingActionIf> actionList = new ArrayList<>();
		List<Color> recentColors = controller.getRecentColors();
		for (Color color : recentColors) {
			actionList.add(new SetVertexColorAction(vertex, color));
		}

		actionList.add(createSeparator());
		actionList.add(chooseColorAction);
		actionList.add(clearColorAction);

		return actionList;
	}

	@Override
	public JButton doCreateButton() {
		return new MultipleActionDockingToolbarButton(this) {
			@Override
			public void setIcon(Icon icon) {
				super.setIcon(colorIcon);
			}

			@Override
			/**
			 * This is used by our button above to show a popup.  We need to override the
			 * value here, since 
			 */
			public Point getLocationOnScreen() {
				if (vertex.isFullScreenMode()) {
					return super.getLocationOnScreen();
				}

				Point buttonPointInVertexComponent = getButtonLocationInGraphComponentPanel();
				Point vertexViewLocation =
					controller.getViewerPointFromVertexPoint(vertex, buttonPointInVertexComponent);

				Component vertexParent = vertex.getComponent().getParent();
				Point point = new Point(vertexViewLocation.x, vertexViewLocation.y);
				SwingUtilities.convertPointToScreen(point, vertexParent);
				return point;
			}

			@Override
			public Point getPopupPoint() {
				if (vertex.isFullScreenMode()) {
					return super.getPopupPoint();
				}

				Point buttonUpperLeftCorner =
					controller.getViewerPointFromVertexPoint(vertex, new Point(0, 0));
				Point buttonBottomLeftCorner =
					controller.getViewerPointFromVertexPoint(vertex, new Point(0, getHeight()));
				int y = buttonBottomLeftCorner.y - buttonUpperLeftCorner.y;
				return new Point(0, y);
			}

			private Point getButtonLocationInGraphComponentPanel() {
				Component parent = getParent();
				JComponent vertexComponentPanel = vertex.getComponent();

				// Start with our (this button) coordinates and add those to our container's
				// value recursively until we reach our vertex panel.  We have to stop there, 
				// since the vertex panel
				int x = getX();
				int y = getY();
				while (parent != vertexComponentPanel) {
					x += parent.getX();
					y += parent.getY();
					parent = parent.getParent();
				}
				return new Point(x, y);
			}
		};
	}

	private class SetVertexColorAction extends DockingAction {
		private final Color color;
		private final FGVertex actionVertex;

		public SetVertexColorAction(FGVertex vertex, Color color) {
			super("SetVertexColor", "");
			this.actionVertex = vertex;
			this.color = color;
			setMenuBarData(new MenuData(new String[] { "Select Color" }, new ColorIcon3D(color)));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			FGColorProvider colorProvider = controller.getColorProvider();
			colorProvider.setVertexColor(actionVertex, color);
		}
	}
}
