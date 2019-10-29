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
package ghidra.app.plugin.core.programtree;

import java.awt.event.MouseEvent;
import java.util.ArrayList;

import javax.swing.JComponent;

import docking.*;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.ViewManagerService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

public class ViewManagerComponentProvider extends ComponentProviderAdapter
		implements ViewManagerService, ViewChangeListener {

	private static final String OLD_NAME = "ProgramTreePlugin";
	private static final String NAME = "Program Tree";

	public static final String CURRENT_VIEW = "Current Viewname";

	private ViewPanel viewPanel;
	private ArrayList<ViewChangeListener> listeners;
	private Program currentProgram;
	private String restoredViewName;

	public ViewManagerComponentProvider(PluginTool tool, String owner) {
		super(tool, NAME, owner, ProgramActionContext.class);
		viewPanel = new ViewPanel(tool, this);
		listeners = new ArrayList<>(3);

		setTitle("Program Trees");
		setHelpLocation(new HelpLocation(owner, getName()));
		setDefaultWindowPosition(WindowPosition.LEFT);

		//
		// Remove the 'name change' calls below some time after version 10.  These calls map
		// this provider to the correct name and owner over the course of 2 renames.
		//

		// This provider used to be name ViewManagerPlugin and owned by ViewManagerPlugin so 
		// register owner/name change
		String oldOwner = "ViewManagerPlugin";
		String oldName = oldOwner;
		String currentOwner = "ProgramTreePlugin";
		String intermediateName = currentOwner;
		ComponentProvider.registerProviderNameOwnerChange(oldName, oldOwner, intermediateName,
			currentOwner);

		// note: it was a mistake above to name the provider the same as the owner; this update
		// fixes that
		String currentName = NAME;
		ComponentProvider.registerProviderNameOwnerChange(intermediateName, currentOwner,
			currentName, currentOwner);
	}

	void serviceAdded(ViewProviderService service) {
		viewPanel.addView(service);
		String viewName = service.getViewName();
		if (viewName.equals(restoredViewName)) {
			// state is being restored, so set the current view now
			restoredViewName = null;
			viewPanel.setCurrentView(viewName);
		}
		else if (viewPanel.getNumberOfViews() == 1) {
			viewName = viewPanel.getCurrentViewName();

			// we only have one view, so force view map events to go out
			viewPanel.setCurrentView(viewName);
		}
	}

	void serviceRemoved(ViewProviderService service) {
		viewPanel.removeView(service);
	}

	public void addViewChangeListener(ViewChangeListener l) {
		if (!listeners.contains(l)) {
			listeners.add(l);
		}
	}

	public void removeViewChangeListener(ViewChangeListener l) {
		listeners.remove(l);
	}

	@Override
	public AddressSetView addToView(ProgramLocation loc) {
		return viewPanel.addToView(loc);
	}

	@Override
	public AddressSetView getCurrentView() {
		return viewPanel.getCurrentView();
	}

	@Override
	public void viewChanged(AddressSetView addrSet) {
		for (int i = 0; i < listeners.size(); i++) {
			ViewChangeListener l = listeners.get(i);
			l.viewChanged(addrSet);
		}
	}

	@Override
	public void viewNameChanged(ViewProviderService vps, String oldName) {
		viewPanel.viewNameChanged(vps, oldName);
	}

	public void setCurrentViewProvider(ViewProviderService vps) {
		viewPanel.setCurrentView(vps.getViewName());
	}

	public void dispose() {
		viewPanel.dispose();
		listeners.clear();
	}

	void writeDataState(SaveState saveState) {
		String viewName = viewPanel.getCurrentViewName();
		if (viewName != null) {
			saveState.putString(CURRENT_VIEW, viewName);
		}
	}

	void readDataState(SaveState saveState) {
		if (saveState != null) {
			restoredViewName = saveState.getString(CURRENT_VIEW, null);
			if (viewPanel.setCurrentView(restoredViewName)) {
				restoredViewName = null; // have the view
			}
			// else wait for serviceAdded to restore the view...
		}
	}

	Object getUndoRedoState(DomainObject domainObject) {
		SaveState saveState = new SaveState();
		writeDataState(saveState);
		return saveState;
	}

	void restoreUndoRedoState(DomainObject domainObject, Object state) {
		readDataState((SaveState) state);
	}

	/**
	 * Get the object under the mouse location for the popup
	 * 
	 * @param event the mouse event that triggered the popup
	 */
	private Object getActivePopupObject(MouseEvent event) {

		if (viewPanel.isTabClick(event)) {
			return viewPanel;
		}
		ViewProviderService vps = viewPanel.getCurrentViewProvider();
		if (vps != null) {
			return vps.getActivePopupObject(event);
		}
		return null;
	}

	@Override
	public ViewProviderService getCurrentViewProvider() {
		return viewPanel.getCurrentViewProvider();
	}

	@Override
	public JComponent getComponent() {
		return viewPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (currentProgram == null) {
			return null;
		}

		if (event != null) {
			return new ProgramActionContext(this, currentProgram, viewPanel,
				getActivePopupObject(event));
		}

		return new ProgramActionContext(this, currentProgram, viewPanel, getFocusedContext());
	}

	private Object getFocusedContext() {
		ViewProviderService vps = getCurrentViewProvider();
		if (vps != null) {
			return vps.getActiveObject();
		}

		return viewPanel;
	}

	@Override
	public void setCurrentViewProvider(String viewName) {
		viewPanel.setCurrentView(viewName);
	}

	public void setCurrentProgram(Program program) {
		currentProgram = program;
	}

}
