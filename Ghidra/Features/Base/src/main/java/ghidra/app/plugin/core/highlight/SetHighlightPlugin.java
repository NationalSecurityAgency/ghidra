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
package ghidra.app.plugin.core.highlight;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.InteriorSelection;
import ghidra.program.util.ProgramSelection;

/**
 * Plugin to set the current selection to be a highlight or vice versa.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Set Highlight From Selection",
	description = "Provides actions for setting a highlight from a selection or setting a selection from a hightlight",
	eventsConsumed = { ProgramHighlightPluginEvent.class }
)
//@formatter:on
public class SetHighlightPlugin extends Plugin {

	private static final String HIGHLIGHT_GROUP = "Highlight";
	private static final String MENU_HIGHLIGHT = "Program Highlight";
	private static final String MENU_SELECTION = "Program Selection";
	private static final String[] SET_HIGHLIGHT_POPUPPATH = { MENU_HIGHLIGHT, "Entire Selection" };
	private static final String[] CLEAR_HIGHLIGHT_POPUPPATH = { MENU_HIGHLIGHT, "Clear" };
	private static final String[] ADD_SELECTION_POPUPPATH = { MENU_HIGHLIGHT, "Add Selection" };
	private static final String[] SUBTRACT_SELECTION_POPUPPATH =
		{ MENU_HIGHLIGHT, "Subtract Selection" };
	private static final String[] SET_SELECTION_POPUPPATH = { MENU_SELECTION, "Entire Highlight" };
	// HIGHLIGHT MANIPULATION ACTIONS
	private DockingAction setHighlightFromSelectionAction;
	private DockingAction clearHighlightAction;
	private DockingAction addSelectionAction;
	private DockingAction subtractSelectionAction;
	// SELECTION MANIPULATION ACTIONS
	private DockingAction setSelectionFromHighlightAction;

	/**
	 * Constructor
	 * @param tool
	 */
	public SetHighlightPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	/**
	 * Create the actions and add them to the tool.
	 */
	private void createActions() {

		int programHighlightSubMenuPosition = 1;

		setHighlightFromSelectionAction =
			new NavigatableContextAction("Set Highlight From Selection", getName()) {
				@Override
				protected void actionPerformed(NavigatableActionContext context) {
					setHighlight(context.getNavigatable(), copySelection(context.getSelection()));
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					return context.hasSelection() && context.getNavigatable().supportsHighlight();
				}
			};
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_SELECTION, MENU_HIGHLIGHT,
				"Entire Selection" }, HIGHLIGHT_GROUP);
		menuData.setMenuSubGroup(Integer.toString(programHighlightSubMenuPosition++));
		setHighlightFromSelectionAction.setMenuBarData(menuData);
		setHighlightFromSelectionAction.setPopupMenuData(new MenuData(SET_HIGHLIGHT_POPUPPATH,
			HIGHLIGHT_GROUP));
		setHighlightFromSelectionAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_H,
			InputEvent.CTRL_DOWN_MASK));
		setHighlightFromSelectionAction
				.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(setHighlightFromSelectionAction);

		clearHighlightAction = new NavigatableContextAction("Remove Highlight", getName()) {
			@Override
			protected void actionPerformed(NavigatableActionContext context) {
				setHighlight(context.getNavigatable(), new ProgramSelection());
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return context.hasHighlight();
			}
		};
		menuData =
			new MenuData(new String[] { ToolConstants.MENU_SELECTION, MENU_HIGHLIGHT, "Clear" },
				HIGHLIGHT_GROUP);
		menuData.setMenuSubGroup(Integer.toString(programHighlightSubMenuPosition++));
		clearHighlightAction.setMenuBarData(menuData);
		clearHighlightAction.setPopupMenuData(new MenuData(CLEAR_HIGHLIGHT_POPUPPATH,
			HIGHLIGHT_GROUP));
		clearHighlightAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(clearHighlightAction);

		addSelectionAction = new NavigatableContextAction("Add Selection To Highlight", getName()) {
			@Override
			protected void actionPerformed(NavigatableActionContext context) {
				ProgramSelection highlight = context.getHighlight();
				highlight = new ProgramSelection(highlight.union(context.getSelection()));
				setHighlight(context.getNavigatable(), highlight);
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return context.hasSelection() && context.hasHighlight();
			}
		};
		menuData =
			new MenuData(new String[] { ToolConstants.MENU_SELECTION, MENU_HIGHLIGHT,
				"Add Selection" }, HIGHLIGHT_GROUP);
		menuData.setMenuSubGroup(Integer.toString(programHighlightSubMenuPosition++));
		addSelectionAction.setMenuBarData(menuData);
		addSelectionAction.setPopupMenuData(new MenuData(ADD_SELECTION_POPUPPATH, HIGHLIGHT_GROUP));
		addSelectionAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(addSelectionAction);

		subtractSelectionAction =
			new NavigatableContextAction("Subtract Selection From Highlight", getName()) {
				@Override
				protected void actionPerformed(NavigatableActionContext context) {
					ProgramSelection highlight = context.getHighlight();
					highlight = new ProgramSelection(highlight.subtract(context.getSelection()));
					setHighlight(context.getNavigatable(), highlight);
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					return context.hasSelection() && context.hasHighlight();
				}
			};
		menuData =
			new MenuData(new String[] { ToolConstants.MENU_SELECTION, MENU_HIGHLIGHT,
				"Subtract Selection" }, HIGHLIGHT_GROUP);
		menuData.setMenuSubGroup(Integer.toString(programHighlightSubMenuPosition++));
		subtractSelectionAction.addToWindowWhen(NavigatableActionContext.class);
		subtractSelectionAction.setMenuBarData(menuData);
		subtractSelectionAction.setPopupMenuData(new MenuData(SUBTRACT_SELECTION_POPUPPATH,
			HIGHLIGHT_GROUP));

		tool.addAction(subtractSelectionAction);

		setSelectionFromHighlightAction =
			new NavigatableContextAction("Set Selection From Highlight", getName()) {
				@Override
				protected void actionPerformed(NavigatableActionContext context) {
					setSelection(context.getNavigatable(), copySelection(context.getHighlight()));
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					return context.hasHighlight();
				}
			};
		setSelectionFromHighlightAction.setMenuBarData(new MenuData(new String[] {
			ToolConstants.MENU_SELECTION, "From Highlight" }, HIGHLIGHT_GROUP));
		setSelectionFromHighlightAction.setPopupMenuData(new MenuData(SET_SELECTION_POPUPPATH,
			HIGHLIGHT_GROUP));
		setSelectionFromHighlightAction
				.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(setSelectionFromHighlightAction);

		tool.setMenuGroup(new String[] { MENU_SELECTION, MENU_HIGHLIGHT }, HIGHLIGHT_GROUP);
	}

	protected void setHighlight(Navigatable navigatable, ProgramSelection highlight) {
		if (navigatable == null) {
			GoToService service = tool.getService(GoToService.class);
			if (service == null) {
				return; // can't do anything
			}
			navigatable = service.getDefaultNavigatable();
		}
		navigatable.setHighlight(highlight);
	}

	protected void setSelection(Navigatable navigatable, ProgramSelection selection) {
		if (navigatable == null) {
			GoToService service = tool.getService(GoToService.class);
			if (service == null) {
				return; // can't do anything
			}
			navigatable = service.getDefaultNavigatable();
		}
		navigatable.setSelection(selection);
	}

	private ProgramSelection copySelection(ProgramSelection selection) {
		if (selection != null) {
			InteriorSelection is = selection.getInteriorSelection();
			if (is != null) {
				InteriorSelection ih =
					new InteriorSelection(is.getFrom(), is.getTo(), is.getStartAddress(),
						is.getEndAddress());
				return new ProgramSelection(ih);
			}
		}
		return new ProgramSelection(selection);
	}

}
