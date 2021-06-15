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
import java.awt.event.MouseEvent;
import java.util.Set;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import docking.ActionContext;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;
import util.CollectionUtils;

/**
 * This panel looks similar in appearance to the LisGraphComponentPanel, with a header, actions 
 * and a body.
 */
public class GroupedFunctionGraphComponentPanel extends AbstractGraphComponentPanel {

	private GenericHeader genericHeader;
	private GroupedFunctionGraphVertex groupVertex;

	private JComponent contentPanel;

	private DockingAction groupAction;
	private DockingAction regroupAction;
	private DockingAction ungroupAction;
	private DockingAction addToGroupAction;

	private SetVertexMostRecentColorAction setVertexMostRecentAction;

	private Color defaultBackgroundColor; // pulled from options
	private Color userDefinedColor;

	private String userText;
	private JTextArea userTextArea;

	GroupedFunctionGraphComponentPanel(FGController controller, GroupedFunctionGraphVertex vertex,
			String groupVertexUserText) {
		super(controller, vertex);
		this.groupVertex = vertex;
		this.userText = groupVertexUserText;
		this.title = createTitle();

		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		this.defaultBackgroundColor = options.getDefaultGroupBackgroundColor();

		setLayout(new BorderLayout());

		genericHeader = new GenericHeader() {
			// overridden to prevent excessive title bar width for long symbol names
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				FormatManager formatManager = getController().getMinimalFormatManager();
				int maxWidth = formatManager.getMaxWidth();
				if (maxWidth <= 0) {
					return preferredSize;
				}

				// don't let a big format, like the function signature, dictate our group width
				maxWidth = Math.min(maxWidth, 300);

				preferredSize.width = maxWidth;
				return preferredSize;
			}
		};

		genericHeader.setComponent(this);
		genericHeader.setTitle(title);

		contentPanel = new JPanel();
		contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		contentPanel.setLayout(new VerticalLayout(0));
		contentPanel.setOpaque(true);
		contentPanel.setBackground(defaultBackgroundColor);

		userTextArea = new JTextArea() {
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				FormatManager formatManager = getController().getMinimalFormatManager();
				int maxWidth = formatManager.getMaxWidth();
				if (maxWidth <= 0) {
					return preferredSize;
				}

				preferredSize.width = maxWidth;
				return preferredSize;
			}
		};
		userTextArea.setOpaque(true);
		userTextArea.setBackground(defaultBackgroundColor);
		userTextArea.setEditable(false);
		userTextArea.setLineWrap(true);
		userTextArea.setWrapStyleWord(true);
		userTextArea.setBorder(BorderFactory.createEmptyBorder());

		// we are not editable; it makes no sense to allow users to drag text
		userTextArea.setDragEnabled(false);

		contentPanel.add(userTextArea);

		setOpaque(true);
		setBackground(defaultBackgroundColor);

		add(genericHeader, BorderLayout.NORTH);
		add(contentPanel, BorderLayout.CENTER);

		BevelBorder beveledBorder =
			(BevelBorder) BorderFactory.createBevelBorder(BevelBorder.RAISED,
				new Color(225, 225, 225), new Color(155, 155, 155), new Color(96, 96, 96),
				new Color(0, 0, 0));
		setBorder(beveledBorder);

		createActions();
		setUserText(userText);

		this.userDefinedColor = maybeUpdateUserDefinedColor();
		if (userDefinedColor != null) {
			doSetBackgroundColor(userDefinedColor);
		}
	}

	/**
	 * A bit of a hack that triggers the text area to update its preferred height now before we 
	 * render so that it doesn't change later.
	 */
	private void updateTextAreaSizeToForceTextLayout() {
		FormatManager formatManager = getController().getMinimalFormatManager();
		int maxWidth = formatManager.getMaxWidth();
		if (maxWidth <= 0) {
			return;
		}
		userTextArea.setSize(maxWidth, Integer.MAX_VALUE);
	}

	private String createTitle() {
		Set<FGVertex> vertices = groupVertex.getVertices();
		int size = vertices.size();
		AddressSetView addresses = vertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		Address maxAddress = addresses.getMaxAddress();
		return "Grouped Vertex - " + size + " vertices [" + minAddress + " - " + maxAddress + "]";
	}

	private void createActions() {
		String firstGroup = "group1";
		String secondGroup = "group2";

		// group
		groupAction = new DockingAction("Group Vertices", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				groupVertices();
			}
		};
		groupAction.setDescription("Combine selected vertices into one vertex");
		ImageIcon imageIcon = ResourceManager.loadImage("images/shape_handles.png");
		groupAction.setToolBarData(new ToolBarData(imageIcon, secondGroup));
		groupAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Group_Vertex_Action_Group"));

		// regroup
		regroupAction = new DockingAction("Regroup Vertices", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				regroupVertices();
			}
		};
		regroupAction.setDescription("Restore vertex and siblings back to group form");
		imageIcon = ResourceManager.loadImage("images/edit-redo.png");
		regroupAction.setToolBarData(new ToolBarData(imageIcon, secondGroup));
		regroupAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Regroup"));

		// ungroup
		ungroupAction = new DockingAction("Ungroup Vertices", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.ungroupVertex(groupVertex);
			}
		};
		ungroupAction.setDescription("Ungroup selected vertices into individual vertex");
		imageIcon = ResourceManager.loadImage("images/shape_ungroup.png");
		ungroupAction.setToolBarData(new ToolBarData(imageIcon, secondGroup));
		ungroupAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Ungroup"));

		// add to group
		addToGroupAction = new DockingAction("Add to Group", FunctionGraphPlugin.class.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addToGroup();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Set<FGVertex> vertices = controller.getSelectedVertices();
				vertices.remove(vertex);

				if (vertices.size() == 0) {
					Msg.showInfo(getClass(), GroupedFunctionGraphComponentPanel.this,
						"Cannot Group 1 Vertex",
						"You must have more than 1 vertex selected to add to this group");
					return false;
				}

				return vertices.size() > 0;
			}
		};
		addToGroupAction.setDescription("Add the selected vertices to this group");
		imageIcon = ResourceManager.loadImage("images/shape_square_add.png");
		addToGroupAction.setToolBarData(new ToolBarData(imageIcon, secondGroup));
		addToGroupAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Group_Add"));

		// color	
		setVertexMostRecentAction = new SetVertexMostRecentColorAction(controller, vertex);
		setVertexMostRecentAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Group_Vertex_Action_Color"));
		Icon icon = setVertexMostRecentAction.getToolbarIcon();
		setVertexMostRecentAction.setToolBarData(new ToolBarData(icon, firstGroup));

		genericHeader.actionAdded(setVertexMostRecentAction);
		genericHeader.actionAdded(ungroupAction);
		genericHeader.actionAdded(addToGroupAction);
		genericHeader.actionAdded(groupAction); // last to be the same as the non-grouped header

		genericHeader.update();
	}

	private void removeRedoAction() {
		genericHeader.actionRemoved(regroupAction);
	}

	private void addRedoAction() {
		GroupHistoryInfo groupInfo = vertex.getGroupInfo();
		regroupAction.setDescription(HTMLUtilities.toHTML(groupInfo.getGroupDescription()));

		genericHeader.actionRemoved(regroupAction);
		genericHeader.actionAdded(regroupAction);
	}

	@Override
	void updateGroupAssociationStatus(boolean groupMember) {
		if (groupMember) {
			addRedoAction();
		}
		else {
			removeRedoAction();
		}
	}

	@Override
	void editLabel(JComponent parentComponent) {
		String oldText = userText;
		String text = controller.promptUserForGroupVertexText(parentComponent, userText,
			groupVertex.getVertices());
		if (text == null || text.equals(oldText)) {
			return;
		}

		setUserText(text);

		groupVertex.userTextChanged(oldText, text);

		controller.repaint();
	}

	String getUserText() {
		return userText;
	}

	private void setUserText(String userText) {
		if (userText == null || userText.isEmpty()) {
			userText = controller.generateGroupVertexDescription(groupVertex.getVertices());
		}
		this.userText = userText;
		userTextArea.setText(userText);

		updateTextAreaSizeToForceTextLayout();
	}

	private void addToGroup() {
		Set<FGVertex> selectedVertices = controller.getSelectedVertices();
		controller.addToGroup(groupVertex, selectedVertices);
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();

		int headerWidth = genericHeader.getPreferredSize().width;
		preferredSize.width = headerWidth;
		return preferredSize;
	}

	private Color maybeUpdateUserDefinedColor() {
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		if (!options.getUpdateGroupColorsAutomatically()) {
			return null;
		}

		//
		// We want to updated the user defined color value if and only if all grouped vertices
		// share the same non-default color.
		//
		Set<FGVertex> vertices = groupVertex.getVertices();
		Color lastColor = null;
		for (FGVertex groupedVertex : vertices) {
			Color currentVertexBackgroundColor = groupedVertex.getBackgroundColor();
			if (lastColor == null) {
				lastColor = currentVertexBackgroundColor;
			}

			Color defaultVertexBackgroundColor = groupedVertex.getDefaultBackgroundColor();
			if (currentVertexBackgroundColor.equals(defaultVertexBackgroundColor)) {
				// if any of the grouped vertices have a default background color, then we will
				// the group as a whole must not share a user defined color
				return null;
			}

			if (!currentVertexBackgroundColor.equals(lastColor)) {
				// we've found a differing user-defined color
				return null;
			}
		}
		return lastColor;
	}

	@Override
	Color getUserDefinedColor() {
		return userDefinedColor;
	}

	@Override
	void restoreColor(Color color) {
		doSetBackgroundColor(color);
	}

	@Override
	void setBackgroundColor(Color color) {
		userDefinedColor = color;
		doSetBackgroundColor(color);
	}

	@Override
	void clearColor() {
		userDefinedColor = null;
		doSetBackgroundColor(defaultBackgroundColor);
	}

	private void doSetBackgroundColor(Color color) {
		setBackground(color);
		contentPanel.setBackground(color);
		userTextArea.setBackground(color);
		controller.removeColor(vertex);
		controller.repaint();

		if (color.equals(defaultBackgroundColor)) {
			return;
		}

		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		if (!options.getUpdateGroupColorsAutomatically()) {
			return;
		}

		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex groupedVertex : vertices) {
			groupedVertex.setBackgroundColor(color);
		}
	}

	@Override
	Color getDefaultBackgroundColor() {
		return defaultBackgroundColor;
	}

	@Override
	Color getBackgroundColor() {
		if (userDefinedColor != null) {
			return userDefinedColor;
		}
		return defaultBackgroundColor;
	}

	@Override
	Color getSelectionColor() {
		Set<FGVertex> vertices = groupVertex.getVertices();
		FGVertex v = CollectionUtils.any(vertices);
		return v.getSelectionColor();
	}

	@Override
	JComponent getHeader() {
		return genericHeader;
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		Component source = event.getComponent();
		if (SwingUtilities.isDescendingFrom(source, genericHeader)) {
			if (!(source instanceof JComponent)) {
				return null;
			}
			JComponent jComponent = (JComponent) source;
			return jComponent.getToolTipText();
		}
// Currently, we do not clip, so there is no need to show the text area's contents
//		else if (source == userTextArea) {
//			return HTMLUtilities.convertToHTML(userTextArea.getText());
//		}
		return null;
	}

	@Override
	ListingModel getListingModel(Address address) {

		FGVertex v = getVertex(address);
		if (v != null) {
			return v.getListingModel(address);
		}

		throw new AssertException(
			"Unexpectedly called for an address not contained by my grouped vertex!");
	}

	@Override
	JComponent getToolTipComponentForEdge(FGEdge edge) {
		return this;
	}

	@Override
	JComponent getToolTipComponentForVertex() {
		return this;
	}

	@Override
	boolean isSelected() {
		return genericHeader.isSelected();
	}

	@Override
	void setSelected(boolean selected) {
		genericHeader.setSelected(selected);
	}

	@Override
	ProgramLocation getProgramLocation() {
		// not sure what the best thing is...for now, just broadcast the first address
		return new ProgramLocation(vertex.getProgram(), vertex.getVertexAddress());
	}

	@Override
	void setCursorPosition(ProgramLocation location) {
		Address address = location.getAddress();
		FGVertex v = getVertex(address);
		if (v != null) {
			v.setFocused(true); // wonky; we have to do this for the location to stick
			v.setProgramLocation(location);
		}

	}

	private FGVertex getVertex(Address a) {
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			if (v.containsAddress(a)) {
				return v;
			}
		}
		return null;
	}

	@Override
	Rectangle getCursorBounds() {
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			Rectangle cursorBounds = v.getCursorBounds();
			if (cursorBounds != null) {
				return cursorBounds;
			}
		}
		return null;
	}

	@Override
	void setProgramSelection(ProgramSelection selection) {
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			v.setProgramSelection(selection);
		}
	}

	@Override
	ProgramSelection getProgramSelection() {
		AddressSet addresses = new AddressSet();
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			ProgramSelection programSelection = v.getProgramSelection();
			if (programSelection == null) {
				continue;
			}
			addresses.add(programSelection);
		}

		return new ProgramSelection(addresses);
	}

	@Override
	String getTextSelection() {
		return null; // can't select text in a group vertex
	}

	@Override
	void setProgramHighlight(ProgramSelection highlight) {
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			v.setProgramHighlight(highlight);
		}
	}

	@Override
	void doSetFocused(boolean focused) {
		genericHeader.setSelected(focused);
	}

	@Override
	void refreshModel() {
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			v.refreshModel();
		}
	}

	@Override
	void refreshDisplay() {

		updateDefaultBackgroundColor();

		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			v.refreshDisplay();
		}
	}

	private void updateDefaultBackgroundColor() {
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		Color newBgColor = options.getDefaultGroupBackgroundColor();
		if (!defaultBackgroundColor.equals(newBgColor)) {
			defaultBackgroundColor = newBgColor;
			if (userDefinedColor == null) {
				doSetBackgroundColor(defaultBackgroundColor);
			}
		}
	}

	@Override
	void refreshDisplayForAddress(Address address) {
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex v : vertices) {
			v.refreshDisplayForAddress(address);
		}
	}

	@Override
	void setFullScreenMode(boolean fullScreen) {
// // 7937:3 (see below)

	}

	@Override
	public boolean isFullScreenMode() {
// 7937:3 - this will probably need to change if our size is based upon a fancy rendering
//		...sounds cool...not sure of the utility though
		return false;
	}

	@Override
	Component getMaximizedViewComponent() {
// 7937:3 - this will need to change if we want to support showing only the vertices inside of
//		    this group vertex.  To make this happen we probably need to be able to have the 
//		    group vertex contain its own graph that we can set on the viewer if the user hits
//		    the full display button.

//		Could create a new GroupVisualizationViewer that uses the vertices/edges contained by
//		the group vertex

		return null;
	}

	@Override
	void dispose() {
		removeAll();
		setVertexMostRecentAction.dispose();
		groupVertex = null;
		super.dispose();
	}
}
