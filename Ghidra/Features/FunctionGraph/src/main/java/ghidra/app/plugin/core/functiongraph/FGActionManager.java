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
package ghidra.app.plugin.core.functiongraph;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.*;

import javax.swing.*;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import edu.uci.ics.jung.graph.Graph;
import generic.theme.GIcon;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.functiongraph.action.*;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

public class FGActionManager {
	private static final String EDGE_HOVER_HIGHLIGHT = "EDGE_HOVER_HIGHLIGHT";
	private static final String EDGE_SELECTION_HIGHLIGHT = "EDGE_SELECTION_HIGHLIGHT";

	// save state key names
	private static final String LAYOUT_NAME = "LAYOUT_NAME";
	private static final String COMPLEX_LAYOUT_NAME = "COMPLEX_LAYOUT_NAME";
	private static final String LAYOUT_CLASS_NAME = "LAYOUT_CLASS_NAME";

	//@formatter:off
	private static final Icon GROUP_ICON = new GIcon("icon.plugin.functiongraph.action.vertex.group");
	private static final Icon GROUP_ADD_ICON = new GIcon("icon.plugin.functiongraph.action.vertex.group.add");
	private static final Icon UNGROUP_ICON = new GIcon("icon.plugin.functiongraph.action.vertex.ungroup");

	private static final Icon EDIT_ICON = new GIcon("icon.plugin.functiongraph.action.vertex.edit.label");
	private static final Icon FULL_SCREEN_ICON = new GIcon("icon.plugin.functiongraph.action.vertex.full.screen");
	private static final Icon XREFS_ICON = new GIcon("icon.plugin.functiongraph.action.vertex.full.screen");
	//@formatter:off

	private PluginTool tool;
	private String owner;
	private FGController controller;

	private ToggleDockingAction togglePopups;

	private MultiStateDockingAction<EdgeDisplayType> vertexHoverModeAction;
	private MultiStateDockingAction<EdgeDisplayType> vertexFocusModeAction;

	private MultiStateDockingAction<FGLayoutProvider> layoutAction;

	public FGActionManager(FGController controller, String owner) {
		this.controller = controller;
		this.owner = owner;
		FgEnv env = controller.getEnv();
		this.tool = env.getTool();
		
		createActions();
	}

	private JComponent getCenterOverComponent() {
		return controller.getViewComponent();
	}
	
	private void addLocalAction(DockingAction action) {
		FgEnv env = controller.getEnv();
		env.addLocalAction(action);
	}
	
	private void createActions() {

		String toolBarGroup1 = "groupA";
		String layoutGroup = "groupB";
		String toolbarEdgeGroup = "groupC";		

		// this is a dependent, hard-coded value pulled from the plugin that creates highlight actions
		String popupSelectionGroup = "Highlight";
		String popupSelectionGroup2 = popupSelectionGroup + "2";
		String popupSelectionGroup3 = popupSelectionGroup + "3";

		// these groups start with z so that they appear below the other elements in the listing popup
		String popupMutateGroup1 = "zamutate.1";
		String popupMutateGroup2 = "zamutate.2";
		String popupDisplayGroup = "zdisplay";
		String popuEndPopupGroup = "zzzoom";		

		int vertexGroupingSubgroupOffset = 1;
		int groupingSubgroupOffset = 1; // sub-sort of the grouping menu

		DockingAction chooseFormatsAction = 
			new DockingAction("Edit Code Block Fields", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					showFormatChooser();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return controller.hasResults();
				}
			};

		// subgroup 3, after the refresh and layout actions
		chooseFormatsAction.setToolBarData(new ToolBarData(
			new GIcon("icon.plugin.functiongraph.action.vertex.edit.format"), layoutGroup, "3"));
		chooseFormatsAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Function_Graph_Action_Format"));

		DockingAction homeAction =
			new DockingAction("Go To Function Entry Point", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					goHome();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return controller.getGraphedFunction() != null;
				}
			};
		homeAction.setToolBarData(
			new ToolBarData(new GIcon("icon.plugin.functiongraph.action.viewer.home"), toolBarGroup1));
		homeAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Function_Graph_Action_Home"));

		DockingAction resetGraphAction = new DockingAction("Reset Graph", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				int choice = OptionDialog.showYesNoDialog(getCenterOverComponent(), "Reset Graph?",
					"<html>Erase all vertex position and grouping information?");
				if (choice != OptionDialog.YES_OPTION) {
					return;
				}

				controller.resetGraph();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return controller.hasResults();
			}
		};
		resetGraphAction.setToolBarData(
			new ToolBarData(new GIcon("icon.plugin.functiongraph.action.viewer.reset"), layoutGroup, "1"));
		resetGraphAction.setDescription("<html>Reloads the graph--All positioning and grouping " +
			"information is <b>lost</b>");
		resetGraphAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Function_Graph_Reload_Graph"));

		addLocalAction(resetGraphAction);

		addLayoutAction(layoutGroup);
		addVertexHoverModeAction(toolbarEdgeGroup);
		addVertexSelectedModeAction(toolbarEdgeGroup);

		//
		// Display transforming actions
		//
		DockingAction zoomOutAction = new DockingAction("Zoom Out", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.zoomOutGraph();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				return !(context instanceof FunctionGraphVertexLocationInFullViewModeActionContext);
			}
		};
		zoomOutAction
				.setPopupMenuData(new MenuData(new String[] { "Zoom Out" }, popuEndPopupGroup));
		zoomOutAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		zoomOutAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Zoom"));

		DockingAction zoomInAction = new DockingAction("Zoom In", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.zoomInGraph();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				return !(context instanceof FunctionGraphVertexLocationInFullViewModeActionContext);
			}
		};
		zoomInAction.setPopupMenuData(new MenuData(new String[] { "Zoom In" }, popuEndPopupGroup));
		zoomInAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		zoomInAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Zoom"));

		DockingAction zoomToWindowAction = new DockingAction("Zoom to Window", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.zoomToWindow();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				return !(context instanceof FunctionGraphVertexLocationInFullViewModeActionContext);
			}
		};
		zoomToWindowAction.setPopupMenuData(
			new MenuData(new String[] { "Zoom to Window" }, popuEndPopupGroup));
		zoomToWindowAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Zoom"));

		DockingAction zoomToVertexAction = new DockingAction("Zoom to Vertex", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				FunctionGraphVertexLocationContextIf vertexContext =
					(FunctionGraphVertexLocationContextIf) context;
				FGVertex vertex = vertexContext.getVertex();
				controller.zoomToVertex(vertex);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {

				if (!(context instanceof FunctionGraphVertexLocationContextIf)) {
					return false;
				}

				FunctionGraphVertexLocationContextIf vertexContext =
					(FunctionGraphVertexLocationContextIf) context;
				FGVertex vertex = vertexContext.getVertex();
				return vertex != null;
			}
		};
		zoomToVertexAction.setPopupMenuData(
			new MenuData(new String[] { "Zoom to Vertex" }, popuEndPopupGroup));
		zoomToVertexAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Zoom"));

		togglePopups = new ToggleDockingAction("Display Popup Windows", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.setPopupsVisible(isSelected());
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (context instanceof FunctionGraphSatelliteViewerActionContext) {
					return true;
				}
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				return !(context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) &&
					!(context instanceof FunctionGraphUneditableVertexLocationActionContext);
			}
		};
		togglePopups.setSelected(true);
		togglePopups.setPopupMenuData(
			new MenuData(new String[] { "Display Popup Windows" }, popupDisplayGroup));
		togglePopups.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Popups"));

		//
		// Vertex Actions
		//
		DockingAction editLabelAction = new DockingAction("Edit Vertex Label", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				FunctionGraphValidGraphActionContextIf graphContext =
					(FunctionGraphValidGraphActionContextIf) context;

				// size guaranteed to be 1
				FGVertex vertex = graphContext.getSelectedVertices().iterator().next();
				vertex.editLabel(getCenterOverComponent());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
					return false;
				}

				FunctionGraphValidGraphActionContextIf graphContext =
					(FunctionGraphValidGraphActionContextIf) context;
				return graphContext.getSelectedVertices().size() == 1;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
					return false;
				}
				return true;
			}
		};
		MenuData menuData = new MenuData(new String[] { "Edit Label" }, popupMutateGroup1);
		menuData.setIcon(EDIT_ICON);
		menuData.setMenuSubGroup(Integer.toString(vertexGroupingSubgroupOffset++));
		editLabelAction.setDescription("Change the label for the code block");
		editLabelAction.setPopupMenuData(menuData);
		editLabelAction
				.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Label"));

		DockingAction fullViewAction = new DockingAction("Vertex View Mode", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				FunctionGraphValidGraphActionContextIf graphContext =
					(FunctionGraphValidGraphActionContextIf) context;

				// size guaranteed to be 1
				FGVertex vertex = graphContext.getSelectedVertices().iterator().next();
				vertex.setFullScreenMode(true);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
					return false;
				}

				FunctionGraphValidGraphActionContextIf graphContext =
					(FunctionGraphValidGraphActionContextIf) context;
				Set<FGVertex> vertices = graphContext.getSelectedVertices();
				if (vertices.size() != 1) {
					return false;
				}

				FGVertex vertex = vertices.iterator().next();
				return !(vertex instanceof GroupedFunctionGraphVertex);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
					return false;
				}
				return true;
			}
		};
		menuData = new MenuData(new String[] { "View Full Screen" }, popupMutateGroup1);
		menuData.setIcon(FULL_SCREEN_ICON);
		menuData.setMenuSubGroup(Integer.toString(vertexGroupingSubgroupOffset++));
		fullViewAction.setDescription("Displays this vertex in use the full Listing format");
		fullViewAction.setPopupMenuData(menuData);
		fullViewAction.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Action_Full_View"));

		DockingAction xrefsAction = new DockingAction("Jump to XRef", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				controller.showXRefsDialog();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				return true;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				return true;
			}
		};
		menuData = new MenuData(new String[] { "Jump to XRef" }, popupMutateGroup1);
		menuData.setIcon(XREFS_ICON);
		menuData.setMenuSubGroup(Integer.toString(vertexGroupingSubgroupOffset++));
		xrefsAction.setPopupMenuData(menuData);
		xrefsAction.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Vertex_Action_XRefs"));

		//
		// Group Actions
		//
		DockingAction groupSelectedVertices =
			new DockingAction("Group Selected Vertices", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					controller.groupSelectedVertices();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}

					FunctionGraphValidGraphActionContextIf graphContext =
						(FunctionGraphValidGraphActionContextIf) context;
					return graphContext.getSelectedVertices().size() > 1;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}
					return true;
				}
			};
		menuData = new MenuData(new String[] { "Group Selected Vertices" }, popupMutateGroup2);
		menuData.setIcon(GROUP_ICON);
		menuData.setMenuSubGroup(Integer.toString(groupingSubgroupOffset++));
		groupSelectedVertices.setPopupMenuData(menuData);
		groupSelectedVertices.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Grouping_Group_Selected_Popup"));

		DockingAction addSelectedVerticesToGroup =
			new DockingAction("Group Selected Vertices", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					addToGroup(context);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}

					FunctionGraphValidGraphActionContextIf graphContext =
						(FunctionGraphValidGraphActionContextIf) context;
					Set<FGVertex> vertices = graphContext.getSelectedVertices();
					if (vertices.size() <= 1) {
						return false;
					}

					//
					// Make sure we have one and only one
					//
					GroupedFunctionGraphVertex groupVertex = null;
					for (FGVertex vertex : vertices) {
						if (vertex instanceof GroupedFunctionGraphVertex) {
							if (groupVertex != null) {
								return false; // already have one group--can't have multiple
							}
							groupVertex = (GroupedFunctionGraphVertex) vertex;
						}
					}

					return groupVertex != null;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}
					return true;
				}
			};
		menuData = new MenuData(new String[] { "Group Selected Vertices - Add to Group" },
			popupMutateGroup2);

		menuData.setIcon(GROUP_ADD_ICON);
		menuData.setMenuSubGroup(Integer.toString(groupingSubgroupOffset++));
		addSelectedVerticesToGroup.setPopupMenuData(menuData);
		addSelectedVerticesToGroup.setHelpLocation(new HelpLocation("FunctionGraphPlugin",
			"Vertex_Grouping_Add_Selected_Vertices_To_Group"));

		DockingAction ungroupSelectedVertices =
			new DockingAction("Ungroup Selected Vertices", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					FunctionGraphValidGraphActionContextIf graphContext =
						(FunctionGraphValidGraphActionContextIf) context;
					Set<FGVertex> selectedVertices = graphContext.getSelectedVertices();
					ungroupVertices(getGroupVertices(selectedVertices));
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}

					FunctionGraphValidGraphActionContextIf graphContext =
						(FunctionGraphValidGraphActionContextIf) context;
					return getGroupVertices(graphContext.getSelectedVertices()).size() > 0;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}
					return true;
				}
			};
		menuData = new MenuData(new String[] { "Ungroup Selected Vertices" }, popupMutateGroup2);

		menuData.setIcon(UNGROUP_ICON);
		menuData.setMenuSubGroup(Integer.toString(groupingSubgroupOffset++));
		ungroupSelectedVertices.setPopupMenuData(menuData);
		ungroupSelectedVertices.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Grouping_Ungroup_Selected_Popup"));

		DockingAction removeFromGroup = new DockingAction("Remove From Group", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				FunctionGraphValidGraphActionContextIf graphContext =
					(FunctionGraphValidGraphActionContextIf) context;
				Set<FGVertex> selectedVertices = graphContext.getSelectedVertices();
				removeFromHistory(selectedVertices);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
					return false;
				}

				FunctionGraphValidGraphActionContextIf graphContext =
					(FunctionGraphValidGraphActionContextIf) context;
				Set<FGVertex> selectedVertices = graphContext.getSelectedVertices();
				if (selectedVertices.isEmpty()) {
					return false;
				}

				return containsUncollapsedVertices(selectedVertices);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
					return false;
				}
				if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
					return false;
				}
				return true;
			}
		};
		menuData = new MenuData(new String[] { "Remove From Group" }, popupMutateGroup2);

		menuData.setMenuSubGroup(Integer.toString(groupingSubgroupOffset++));
		removeFromGroup.setPopupMenuData(menuData);
		removeFromGroup.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Grouping_Remove_From_Group"));

		DockingAction ungroupAllVertices =
			new DockingAction("Ungroup All Vertices", owner) {
				@Override
				public void actionPerformed(ActionContext context) {

					int choice = OptionDialog.showYesNoDialog(getCenterOverComponent(),
						"Ungroup All Vertices?", "Ungroup all grouped vertices?");
					if (choice != OptionDialog.YES_OPTION) {
						return;
					}
					controller.ungroupAllVertices();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}

					return getGroupVertices(getAllVertices()).size() > 0;
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					if (!(context instanceof FunctionGraphValidGraphActionContextIf)) {
						return false;
					}
					if (context instanceof FunctionGraphVertexLocationInFullViewModeActionContext) {
						return false;
					}
					return true;
				}
			};

		menuData = new MenuData(new String[] { "Ungroup All Vertices" }, popupMutateGroup2);
		menuData.setMenuSubGroup(Integer.toString(groupingSubgroupOffset++));
		ungroupAllVertices.setPopupMenuData(menuData);
		ungroupAllVertices.setHelpLocation(
			new HelpLocation("FunctionGraphPlugin", "Vertex_Grouping_Ungroup_All_Popup"));


		//
		// Selection Actions
		//
		String selectionMenuName = "Program Selection";
		DockingAction selectHoveredEdgesAction =
			new DockingAction("Make Selection From Hovered Edges", owner) {

				@Override
				public void actionPerformed(ActionContext context) {
					FunctionGraphVertexLocationContextIf fgContext =
						(FunctionGraphVertexLocationContextIf) context;
					VertexActionContextInfo vertexInfo = fgContext.getVertexInfo();
					AddressSet addresses = vertexInfo.getHoveredVertexAddresses();
					makeSelectionFromAddresses(addresses);
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					return !(context instanceof FunctionGraphSatelliteViewerActionContext);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (!(context instanceof FunctionGraphVertexLocationContextIf)) {
						return false;
					}
					FunctionGraphVertexLocationContextIf fgContext =
						(FunctionGraphVertexLocationContextIf) context;
					VertexActionContextInfo vertexInfo = fgContext.getVertexInfo();
					AddressSet addresses = vertexInfo.getHoveredVertexAddresses();
					return !addresses.isEmpty();
				}
			};
		selectHoveredEdgesAction.setPopupMenuData(new MenuData(
			new String[] { selectionMenuName, "From Hovered Edges" }, popupSelectionGroup2));
		selectHoveredEdgesAction
				.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Path_Selection"));

		DockingAction selectFocusedEdgesAction =
			new DockingAction("Make Selection From Focused Edges", owner) {

				@Override
				public void actionPerformed(ActionContext context) {
					FunctionGraphVertexLocationContextIf fgContext =
						(FunctionGraphVertexLocationContextIf) context;
					VertexActionContextInfo vertexInfo = fgContext.getVertexInfo();
					AddressSet addresses = vertexInfo.getSelectedVertexAddresses();
					makeSelectionFromAddresses(addresses);
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					return !(context instanceof FunctionGraphSatelliteViewerActionContext);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					if (!(context instanceof FunctionGraphVertexLocationContextIf)) {
						return false;
					}
					FunctionGraphVertexLocationContextIf fgContext =
						(FunctionGraphVertexLocationContextIf) context;
					VertexActionContextInfo vertexInfo = fgContext.getVertexInfo();
					AddressSet addresses = vertexInfo.getSelectedVertexAddresses();
					return !addresses.isEmpty();
				}
			};
		selectFocusedEdgesAction.setPopupMenuData(new MenuData(
			new String[] { selectionMenuName, "From Focused Edges" }, popupSelectionGroup2));
		selectFocusedEdgesAction
				.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Path_Selection"));

		DockingAction clearCurrentSelectionAction =
			new DockingAction("Clear Current Selection", owner) {

				@Override
				public void actionPerformed(ActionContext context) {
					clearGraphSelection();
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					return (context instanceof FunctionGraphValidGraphActionContextIf);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					ProgramSelection selection = controller.getSelection();
					return selection != null && !selection.isEmpty();
				}
			};
		clearCurrentSelectionAction.setPopupMenuData(new MenuData(
			new String[] { selectionMenuName, "Clear Graph Selection" }, popupSelectionGroup3));
		clearCurrentSelectionAction
				.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Path_Selection"));

		DockingAction selectAllAction =
			new DockingAction("Select All Code Units", owner) {

				@Override
				public void actionPerformed(ActionContext context) {

					AddressSet addresses = null;
					Collection<FGVertex> selectedVertices = controller.getSelectedVertices();
					if (selectedVertices.size() > 0) {
						addresses = getAddressesForVertices(selectedVertices);
					}
					// if no vertex is selected, then just select all code blocks in the graph
					else {
						FGData functionGraphData = controller.getFunctionGraphData();
						FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
						Graph<FGVertex, FGEdge> graph = functionGraph;
						addresses = getAddressesForVertices(graph.getVertices());
					}

					makeSelectionFromAddresses(addresses);
				}

				@Override
				public boolean isValidContext(ActionContext context) {
					return (context instanceof FunctionGraphValidGraphActionContextIf);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return isValidContext(context);
				}

				@Override
				public boolean isAddToPopup(ActionContext context) {
					return isValidContext(context);
				}
			};
		selectAllAction
				.setKeyBindingData(new KeyBindingData(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK));
		selectAllAction.setPopupMenuData(new MenuData(
			new String[] { selectionMenuName, "Select All Code Units" }, popupSelectionGroup3));
		selectAllAction
				.setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Code_Unit_Selection"));

		addLocalAction(chooseFormatsAction);
		addLocalAction(homeAction);
		addLocalAction(zoomInAction);
		addLocalAction(zoomOutAction);
		addLocalAction(zoomToVertexAction);
		addLocalAction(zoomToWindowAction);

		addLocalAction(editLabelAction);
		addLocalAction(fullViewAction);
		addLocalAction(xrefsAction);

		addLocalAction(groupSelectedVertices);
		addLocalAction(addSelectedVerticesToGroup);
		addLocalAction(removeFromGroup);
		addLocalAction(ungroupSelectedVertices);
		addLocalAction(ungroupAllVertices);
		addLocalAction(togglePopups);

		addLocalAction(selectAllAction);
		addLocalAction(selectHoveredEdgesAction);
		addLocalAction(selectFocusedEdgesAction);
		addLocalAction(clearCurrentSelectionAction);

		// this does two things: 1) allows us to subgroup the pull-right menu and 2) it matches
		// the organization of the highlight and selection actions from the main listing
		tool.setMenuGroup(new String[] { selectionMenuName }, popupSelectionGroup);

	}

	private void addLayoutAction(String group) {

		HelpLocation layoutHelpLocation =
			new HelpLocation("FunctionGraphPlugin", "Function_Graph_Action_Layout");

		layoutAction = new MultiStateDockingAction<>("Relayout Graph", owner, 
				KeyBindingType.SHARED) {

			@Override
			public void actionPerformed(ActionContext context) {
				// this callback is when the user clicks the button
				FGLayoutProvider currentUserData = getCurrentUserData();
				changeLayout(currentUserData);
			}

			@Override
			public void actionStateChanged(ActionState<FGLayoutProvider> newActionState,
					EventTrigger trigger) {
				changeLayout(newActionState.getUserData());
				if (trigger != EventTrigger.API_CALL) {
					tool.setConfigChanged(true);
				}
			}
		};
		layoutAction.setGroup(group);
		layoutAction.setSubGroup("2"); // 2 after refresh, which is 1
		layoutAction.setHelpLocation(layoutHelpLocation);

		// This icon will display when the action has no icon.   This allows actions with no good
		// icon to be blank in the menu, but to use this icon on the toolbar.
		layoutAction.setDefaultIcon(new GIcon("icon.plugin.functiongraph.action.viewer.layout"));

		List<ActionState<FGLayoutProvider>> actionStates = loadActionStatesForLayoutProviders();
		for (ActionState<FGLayoutProvider> actionState : actionStates) {
			layoutAction.addActionState(actionState);
		}

		addLocalAction(layoutAction);
	}

	private void changeLayout(FGLayoutProvider layout) {
		controller.changeLayout(layout);
	}

	private List<ActionState<FGLayoutProvider>> loadActionStatesForLayoutProviders() {
		FgEnv env = controller.getEnv();
		List<FGLayoutProvider> layoutInstances = env.getLayoutProviders();
		return createActionStates(layoutInstances);
	}

	private List<ActionState<FGLayoutProvider>> createActionStates(
			List<FGLayoutProvider> layoutProviders) {
		List<ActionState<FGLayoutProvider>> list = new ArrayList<>();
		for (FGLayoutProvider layout : layoutProviders) {

			ActionState<FGLayoutProvider> layoutState =
				new ActionState<>(layout.getLayoutName(), layout.getActionIcon(), layout);
			layoutState.setHelpLocation(layout.getHelpLocation());
			list.add(layoutState);
		}

		return list;
	}

	private void setLayoutActionStateByClassName(String layoutClassName, String layoutName) {

		if (layoutName == null) {
			return; // this may be null when coming from an older version of Ghidra
		}

		List<ActionState<FGLayoutProvider>> states = layoutAction.getAllActionStates();
		for (ActionState<FGLayoutProvider> state : states) {
			FGLayoutProvider layoutProvider = state.getUserData();
			String stateLayoutName = layoutProvider.getLayoutName();
			if (stateLayoutName.equals(layoutName)) {
				layoutAction.setCurrentActionState(state);
				return;
			}
		}
	}

	private void addVertexHoverModeAction(String group) {

		//@formatter:off
		Icon pathsToVertexIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.to.vertex");
		Icon pathsFromVertexIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.from.vertex");
		Icon pathsFromToVertexIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.from.to.vertex");
		Icon pathsIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.all");
		Icon cyclesIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.cycles");
		Icon forwardScopedIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.scoped.flow.forward");
		Icon reverseScopedIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.scoped.flow.reverse");
		Icon nothingIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.off");
		//@formatter:off

		HelpLocation pathHelpLocation =
			new HelpLocation("FunctionGraphPlugin", "Path_Highlight_Actions");
		ActionState<EdgeDisplayType> pathsToVertexState = new ActionState<>("Show Paths To Block",
			pathsToVertexIcon, EdgeDisplayType.PathsToVertex);
		pathsToVertexState.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> pathsFromVertexState = new ActionState<>(
			"Show Paths From Block", pathsFromVertexIcon, EdgeDisplayType.PathsFromVertex);
		pathsFromVertexState.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> pathsFromToVertexState = new ActionState<>(
			"Show Paths To/From Block", pathsFromToVertexIcon, EdgeDisplayType.PathsFromToVertex);
		pathsFromToVertexState.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> cyclesState =
			new ActionState<>("Show Loops Containing Block", cyclesIcon, EdgeDisplayType.Cycles);
		cyclesState.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> pathsState = new ActionState<>(
			"Show Paths From Focus to Hover", pathsIcon, EdgeDisplayType.PathsFromVertexToVertex);
		pathsState.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> pathsForwardScopedFlow =
			new ActionState<>("Show Scoped Flow From Block", forwardScopedIcon,
				EdgeDisplayType.ScopedFlowsFromVertex);
		pathsForwardScopedFlow.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> pathsReverseScopedFlow = new ActionState<>(
			"Show Scoped Flow To Block", reverseScopedIcon, EdgeDisplayType.ScopedFlowsToVertex);
		pathsReverseScopedFlow.setHelpLocation(pathHelpLocation);

		ActionState<EdgeDisplayType> offState =
			new ActionState<>("Off", nothingIcon, EdgeDisplayType.Off);
		offState.setHelpLocation(pathHelpLocation);

		vertexHoverModeAction =
			new MultiStateDockingAction<>("Block Hover Mode", owner) {

				@Override
				public void actionStateChanged(ActionState<EdgeDisplayType> newActionState,
						EventTrigger trigger) {
					EdgeDisplayType displayType = newActionState.getUserData();
					controller.setVertexHoverPathHighlightMode(
						displayType.getAsPathHighlightHoverMode());
					tool.setConfigChanged(true);
				}
			};
		vertexHoverModeAction.setGroup(group);
		vertexHoverModeAction.setHelpLocation(pathHelpLocation);

		vertexHoverModeAction.addActionState(offState);
		vertexHoverModeAction.addActionState(pathsForwardScopedFlow);
		vertexHoverModeAction.addActionState(pathsReverseScopedFlow);
		vertexHoverModeAction.addActionState(pathsFromToVertexState);
		vertexHoverModeAction.addActionState(pathsFromVertexState);
		vertexHoverModeAction.addActionState(pathsToVertexState);
		vertexHoverModeAction.addActionState(cyclesState);
		vertexHoverModeAction.addActionState(pathsState);

		vertexHoverModeAction.setCurrentActionState(pathsForwardScopedFlow);

		addLocalAction(vertexHoverModeAction);

	}

	private void addVertexSelectedModeAction(String group) {

		//@formatter:off
		Icon pathsToVertexIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.to.vertex");
		Icon pathsFromVertexIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.from.vertex");
		Icon pathsFromToVertexIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.paths.from.to.vertex");
		Icon cyclesIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.cycles");
		Icon allCyclesIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.cycles.all");
		Icon forwardScopedIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.scoped.flow.forward");
		Icon reverseScopedIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.scoped.flow.reverse");
		Icon nothingIcon = new GIcon("icon.plugin.functiongraph.action.viewer.vertex.hover.off");
		//@formatter:off


		HelpLocation pathHelpLocation =
			new HelpLocation("FunctionGraphPlugin", "Path_Highlight_Actions");
		ActionState<EdgeDisplayType> pathsToVertexState = new ActionState<>("Show Paths To Block",
			pathsToVertexIcon, EdgeDisplayType.PathsToVertex);
		pathsToVertexState.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> pathsFromVertexState = new ActionState<>(
			"Show Paths From Block", pathsFromVertexIcon, EdgeDisplayType.PathsFromVertex);
		pathsFromVertexState.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> pathsFromToVertexState = new ActionState<>(
			"Show Paths To/From Block", pathsFromToVertexIcon, EdgeDisplayType.PathsFromToVertex);
		pathsFromToVertexState.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> cyclesState =
			new ActionState<>("Show Loops Containing Block", cyclesIcon, EdgeDisplayType.Cycles);
		cyclesState.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> allCyclesState = new ActionState<>(
			"Show All Loops In Function", allCyclesIcon, EdgeDisplayType.AllCycles);
		allCyclesState.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> pathsForwardScopedFlow =
			new ActionState<>("Show Scoped Flow From Block", forwardScopedIcon,
				EdgeDisplayType.ScopedFlowsFromVertex);
		pathsForwardScopedFlow.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> pathsReverseScopedFlow = new ActionState<>(
			"Show Scoped Flow To Block", reverseScopedIcon, EdgeDisplayType.ScopedFlowsToVertex);
		pathsReverseScopedFlow.setHelpLocation(pathHelpLocation);
		ActionState<EdgeDisplayType> offState =
			new ActionState<>("Off", nothingIcon, EdgeDisplayType.Off);
		offState.setHelpLocation(pathHelpLocation);

		vertexFocusModeAction =
			new MultiStateDockingAction<>("Block Focus Mode", owner) {

				@Override
				public void actionStateChanged(ActionState<EdgeDisplayType> newActionState,
						EventTrigger trigger) {
					EdgeDisplayType displayType = newActionState.getUserData();
					controller.setVertexFocusPathHighlightMode(
						displayType.getAsPathHighlightHoverMode());
					tool.setConfigChanged(true);
				}
			};
		vertexFocusModeAction.setGroup(group);
		vertexFocusModeAction.setHelpLocation(pathHelpLocation);

		vertexFocusModeAction.addActionState(offState);
		vertexFocusModeAction.addActionState(pathsForwardScopedFlow);
		vertexFocusModeAction.addActionState(pathsReverseScopedFlow);
		vertexFocusModeAction.addActionState(pathsFromToVertexState);
		vertexFocusModeAction.addActionState(pathsFromVertexState);
		vertexFocusModeAction.addActionState(pathsToVertexState);
		vertexFocusModeAction.addActionState(cyclesState);
		vertexFocusModeAction.addActionState(allCyclesState);

		vertexFocusModeAction.setCurrentActionState(allCyclesState);

		addLocalAction(vertexFocusModeAction);
	}

	private void clearGraphSelection() {
		// assume that we have a selection or we would not have gotten called
		FGData functionGraphData = controller.getFunctionGraphData();
		Function function = functionGraphData.getFunction();
		AddressSetView functionBody = function.getBody();
		ProgramSelection selection = controller.getSelection();
		
		AddressSet subtraction = selection.subtract(functionBody);
		ProgramSelection programSelectionWithoutGraphBody = new ProgramSelection(subtraction);
		FgEnv env = controller.getEnv();
		Program program = env.getProgram();
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Spoof!",
					programSelectionWithoutGraphBody, program));
	}

	private Set<FGVertex> getAllVertices() {
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		return new HashSet<>(graph.getVertices());
	}

	private Set<GroupedFunctionGraphVertex> getGroupVertices(Set<FGVertex> vertices) {
		HashSet<GroupedFunctionGraphVertex> groupVertices = new HashSet<>();
		for (FGVertex vertex : vertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				groupVertices.add((GroupedFunctionGraphVertex) vertex);
			}
		}
		return groupVertices;
	}

	private boolean containsUncollapsedVertices(Set<FGVertex> selectedVertices) {
		for (FGVertex vertex : selectedVertices) {
			if (vertex.isUncollapsedGroupMember()) {
				return true;
			}
		}
		return false;
	}

	private void addToGroup(ActionContext context) {
		FunctionGraphValidGraphActionContextIf graphContext =
			(FunctionGraphValidGraphActionContextIf) context;
		GroupedFunctionGraphVertex groupVertex = null;
		Set<FGVertex> vertices = new HashSet<>(graphContext.getSelectedVertices());
		for (FGVertex vertex : vertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				groupVertex = (GroupedFunctionGraphVertex) vertex;
			}
		}
		controller.addToGroup(groupVertex, vertices);
	}

	private void showFormatChooser() {
		controller.showFormatChooser();
	}

	private void goHome() {
		Function function = controller.getGraphedFunction();
		FgEnv env = controller.getEnv();
		Program program = env.getProgram();
		ProgramLocation homeLocation = new ProgramLocation(program, function.getEntryPoint());
		controller.display(program, homeLocation);
	}

	private AddressSet getAddressesForVertices(Collection<FGVertex> vertices) {
		AddressSet addresses = new AddressSet();
		for (FGVertex vertex : vertices) {
			addresses.add(vertex.getAddresses());
		}
		return addresses;
	}

	private void makeSelectionFromAddresses(AddressSet addresses) {
		ProgramSelection selection = new ProgramSelection(addresses);
		FgEnv env = controller.getEnv();
		Program program = env.getProgram();
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Spoof!", selection, program));
	}

	private void ungroupVertices(Set<GroupedFunctionGraphVertex> groupVertices) {

		int size = groupVertices.size();
		if (size == 0) {
			return;
		}

		String vertexString = size == 1 ? "1 group vertex" : size + " group vertices";

		int choice = OptionDialog.showYesNoDialog(getCenterOverComponent(), "Ungroup Vertices?",
			"Ungroup " + vertexString + "?");
		if (choice != OptionDialog.YES_OPTION) {
			return;
		}

		for (GroupedFunctionGraphVertex groupVertex : groupVertices) {
			controller.ungroupVertex(groupVertex);
		}
	}

	private void removeFromHistory(Set<FGVertex> vertices) {
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		for (FGVertex vertex : vertices) {
			functionGraph.removeFromGroupHistory(vertex);
		}
	}

	void setEdgeFocusMode(EdgeDisplayType edgeDisplayType) {
		vertexFocusModeAction.setCurrentActionStateByUserData(edgeDisplayType);
	}

	void setEdgeHoverMode(EdgeDisplayType edgeDisplayType) {
		vertexHoverModeAction.setCurrentActionStateByUserData(edgeDisplayType);
	}

	EdgeDisplayType getCurrentFocusMode() {
		return vertexFocusModeAction.getCurrentUserData();
	}

	EdgeDisplayType getCurrentHoverMode() {
		return vertexHoverModeAction.getCurrentUserData();
	}

	void popupVisibilityChanged(boolean visible) {
		togglePopups.setSelected(visible);
	}

	void setCurrentActionState(ActionState<FGLayoutProvider> state) {
		layoutAction.setCurrentActionState(state);
	}

	void setLayouts(List<FGLayoutProvider> layouts) {
		List<ActionState<FGLayoutProvider>> states = createActionStates(layouts);
		layoutAction.setActionStates(states);
	}

	ActionState<FGLayoutProvider> getCurrentLayoutState() {
		return layoutAction.getCurrentState();
	}

	void readConfigState(SaveState saveState) {
		EdgeDisplayType hoverState = saveState.getEnum(EDGE_HOVER_HIGHLIGHT,
			vertexHoverModeAction.getCurrentState().getUserData());
		vertexHoverModeAction.setCurrentActionStateByUserData(hoverState);

		EdgeDisplayType selectedState = saveState.getEnum(EDGE_SELECTION_HIGHLIGHT,
			vertexFocusModeAction.getCurrentState().getUserData());
		vertexFocusModeAction.setCurrentActionStateByUserData(selectedState);

		FGLayoutProvider layoutProvider = layoutAction.getCurrentUserData();
		SaveState layoutState = saveState.getSaveState(COMPLEX_LAYOUT_NAME);
		if (layoutState != null) {
			String layoutName = layoutState.getString(LAYOUT_NAME, layoutProvider.getLayoutName());
			String layoutClassName =
				layoutState.getString(LAYOUT_CLASS_NAME, layoutProvider.getClass().getName());
			setLayoutActionStateByClassName(layoutClassName, layoutName);
		}
	}

	void writeConfigState(SaveState saveState) {
		saveState.putEnum(EDGE_HOVER_HIGHLIGHT, vertexHoverModeAction.getCurrentUserData());
		saveState.putEnum(EDGE_SELECTION_HIGHLIGHT, vertexFocusModeAction.getCurrentUserData());

		FGLayoutProvider layoutProvider = layoutAction.getCurrentUserData();

		SaveState layoutState = new SaveState(COMPLEX_LAYOUT_NAME);
		String layoutName = layoutProvider.getLayoutName();
		layoutState.putString(LAYOUT_NAME, layoutName);
		layoutState.putString(LAYOUT_CLASS_NAME, layoutProvider.getClass().getName());
		saveState.putSaveState(COMPLEX_LAYOUT_NAME, layoutState);
	}
}
