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

public class StubVTController implements VTController {

	@Override
	public void addListener(VTControllerListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeListener(VTControllerListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public VTSession getSession() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void openVersionTrackingSession(DomainFile domainFile) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void openVersionTrackingSession(VTSession session) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean closeVersionTrackingSession() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void closeCurrentSessionIgnoringChanges() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dispose() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getSourceProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getDestinationProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean checkForUnSavedChanges() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressCorrelation getCorrelator(Function source, Function destination) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressCorrelation getCorrelator(Data source, Data destination) {
		throw new UnsupportedOperationException();
	}

	@Override
	public VTMarkupItem getCurrentMarkupForLocation(ProgramLocation location, Program program) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<VTMarkupItem> getMarkupItems(ActionContext context) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ToolOptions getOptions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Component getParentComponent() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ServiceProvider getServiceProvider() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getVersionTrackingSessionName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void refresh() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MatchInfo getMatchInfo() {
		throw new UnsupportedOperationException();
	}

	@Override
	public PluginTool getTool() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSelectedMatch(VTMatch match) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MatchInfo getMatchInfo(VTMatch match) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSelectedMarkupItem(VTMarkupItem markupItem) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressCorrelatorManager getCorrelator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void gotoSourceLocation(ProgramLocation location) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void gotoDestinationLocation(ProgramLocation location) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void runVTTask(VtTask task) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getSourceSymbol(VTAssociation association) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getDestinationSymbol(VTAssociation association) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getSelectionInSourceTool() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getSelectionInDestinationTool() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSelectionInSourceTool(AddressSetView sourceSet) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSelectionInDestinationTool(AddressSetView destinationSet) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void markupItemStatusChanged(VTMarkupItem markupItem) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ColorizingService getSourceColorizingService() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ColorizingService getDestinationColorizingService() {
		throw new UnsupportedOperationException();
	}

}
