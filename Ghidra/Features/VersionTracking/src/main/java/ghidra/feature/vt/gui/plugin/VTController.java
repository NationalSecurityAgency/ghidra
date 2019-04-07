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
package ghidra.feature.vt.gui.plugin;

import java.awt.Component;
import java.util.List;

import docking.ActionContext;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.task.VtTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.ProgramLocation;

public interface VTController {

	public static final String VERSION_TRACKING_OPTIONS_NAME = "Version Tracking";

	public void addListener(VTControllerListener listener);

	public void removeListener(VTControllerListener listener);

//	public VTSessionState getSessionState();

	public VTSession getSession();

	public void openVersionTrackingSession(DomainFile domainFile);

	public void openVersionTrackingSession(VTSession session);

	public boolean closeVersionTrackingSession();

	public void closeCurrentSessionIgnoringChanges();

	public void dispose();

	public void readConfigState(SaveState saveState);

	public void writeConfigState(SaveState saveState);

	public Program getSourceProgram();

	public Program getDestinationProgram();

	// returns true if the operation was not cancelled.
	public boolean checkForUnSavedChanges();

	public AddressCorrelation getCorrelator(Function source, Function destination);

	public AddressCorrelation getCorrelator(Data source, Data destination);

	public VTMarkupItem getCurrentMarkupForLocation(ProgramLocation location, Program program);

	public List<VTMarkupItem> getMarkupItems(ActionContext context);

	public ToolOptions getOptions();

	public Component getParentComponent();

	public ServiceProvider getServiceProvider();

	public String getVersionTrackingSessionName();

	public void refresh();

	public MatchInfo getMatchInfo();

	public PluginTool getTool();

	public void setSelectedMatch(VTMatch match);

	public MatchInfo getMatchInfo(VTMatch match);

	public void setSelectedMarkupItem(VTMarkupItem markupItem);

	public AddressCorrelatorManager getCorrelator();

	public void domainObjectChanged(DomainObjectChangedEvent ev);

	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue);

	public void gotoSourceLocation(ProgramLocation location);

	public void gotoDestinationLocation(ProgramLocation location);

	/**
	 * Runs VT tasks, listening for destination program changes and updates undo/redo state
	 * accordingly.
	 */
	public void runVTTask(VtTask task);

	public Symbol getSourceSymbol(VTAssociation association);

	public Symbol getDestinationSymbol(VTAssociation association);

	/**
	 * Gets the address set for the current selection in the Source Tool.
	 * @return the current selection or null.
	 */
	public AddressSetView getSelectionInSourceTool();

	/**
	 * Gets the address set for the current selection in the Destination Tool.
	 * @return the current selection or null.
	 */
	public AddressSetView getSelectionInDestinationTool();

	/**
	 * Sets the selection in the source tool to the given address set.
	 * @param sourceSet the addressSet to set the source tool's selection.
	 */
	public void setSelectionInSourceTool(AddressSetView sourceSet);

	/**
	 * Sets the selection in the destination tool to the given address set.
	 * @param destinationSet the addressSet to set the destination tool's selection.
	 */
	public void setSelectionInDestinationTool(AddressSetView destinationSet);

	public void markupItemStatusChanged(VTMarkupItem markupItem);

	public ColorizingService getSourceColorizingService();

	public ColorizingService getDestinationColorizingService();
}
