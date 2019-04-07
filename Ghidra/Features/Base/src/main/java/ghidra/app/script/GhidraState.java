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
package ghidra.app.script;

import java.util.HashMap;
import java.util.Set;

import javax.swing.JOptionPane;

import ghidra.app.events.*;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;

/**
 * Represents the current state of a Ghidra tool
 */
public class GhidraState {
	private PluginTool tool;
	private Program currentProgram;
	private ProgramLocation currentLocation;
	private ProgramSelection currentSelection;
	private ProgramSelection currentHighlight;
	private HashMap<String, Object> envmap = new HashMap<>();
	private GatherParamPanel gatherParamPanel = null;
	private Project project;
	private final boolean isGlobalState;

	/**
	 * Constructs a new Ghidra state.
	 * @param tool       the current tool
	 * @param project	 the current project
	 * @param program    the current program
	 * @param location   the current location
	 * @param selection  the current selection
	 * @param highlight  the current highlight
	 */
	public GhidraState(PluginTool tool, Project project, Program program, ProgramLocation location,
			ProgramSelection selection, ProgramSelection highlight) {
		this.tool = tool;
		this.project = project;
		this.currentProgram = program;
		this.currentLocation = location;
		this.currentSelection = selection;
		this.currentHighlight = highlight;
		this.isGlobalState = true;
		if (!SystemUtilities.isInHeadlessMode()) {
			gatherParamPanel = new GatherParamPanel(this);
		}
	}

	public GhidraState(GhidraState state) {
		this.tool = state.tool;
		this.currentProgram = state.currentProgram;
		this.currentLocation = state.currentLocation;
		this.currentSelection = state.currentSelection;
		this.currentHighlight = state.currentHighlight;
		this.envmap = new HashMap<>(state.envmap);
		this.project = state.project;
		this.isGlobalState = false;
	}

	/**
	 * Returns the current tool.
	 * @return the current tool
	 */
	public PluginTool getTool() {
		return tool;
	}

	/**
	 * Returns the current project.
	 * @return the current project
	 */
	public Project getProject() {
		return project;
	}

	/**
	 * Returns the current program.
	 * @return the current program
	 */
	public Program getCurrentProgram() {
		return currentProgram;
	}

	/**
	 * Sets the current program.
	 */
	public void setCurrentProgram(Program program) {
		if (program == currentProgram) {
			return;
		}
		this.currentProgram = program;
		if (gatherParamPanel == null) {
			return;
		}
		gatherParamPanel.currentProgramChanged();
	}

	public Address getCurrentAddress() {
		return currentLocation != null ? currentLocation.getAddress() : null;

	}

	public void setCurrentAddress(Address address) {
		if (SystemUtilities.isEqual(address, getCurrentAddress())) {
			return;
		}
		setCurrentLocation(new ProgramLocation(currentProgram, address));
	}

	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	public void setCurrentLocation(ProgramLocation location) {
		if (SystemUtilities.isEqual(currentLocation, location)) {
			return;
		}
		this.currentLocation = location;
		if (isGlobalState && tool != null) {
			PluginEvent ev = new ProgramLocationPluginEvent(null, location, currentProgram);
			tool.firePluginEvent(ev);
		}
	}

	public ProgramSelection getCurrentHighlight() {
		return currentHighlight;
	}

	public void setCurrentHighlight(ProgramSelection highlight) {
		if (SystemUtilities.isEqual(currentHighlight, highlight)) {
			return;
		}
		this.currentHighlight = highlight;
		if (isGlobalState && tool != null) {
			ProgramSelection sel = currentHighlight != null ? currentHighlight
					: new ProgramSelection(new AddressSet());
			PluginEvent evt =
				new ProgramHighlightPluginEvent(getClass().getName(), sel, currentProgram);
			tool.firePluginEvent(evt);
		}
	}

	public ProgramSelection getCurrentSelection() {
		return currentSelection;
	}

	public void setCurrentSelection(ProgramSelection selection) {
		if (SystemUtilities.isEqual(currentSelection, selection)) {
			return;
		}
		this.currentSelection = selection;
		if (isGlobalState && tool != null) {
			ProgramSelection sel = currentSelection != null ? currentSelection
					: new ProgramSelection(new AddressSet());
			PluginEvent evt =
				new ProgramSelectionPluginEvent(getClass().getName(), sel, currentProgram);
			tool.firePluginEvent(evt);
		}
	}

	public void addEnvironmentVar(String name, byte value) {
		envmap.put(name, new Byte(value));
	}

	public void addEnvironmentVar(String name, short value) {
		envmap.put(name, new Short(value));
	}

	public void addEnvironmentVar(String name, int value) {
		envmap.put(name, new Integer(value));
	}

	public void addEnvironmentVar(String name, long value) {
		envmap.put(name, new Long(value));
	}

	public void addEnvironmentVar(String name, float value) {
		envmap.put(name, new Float(value));
	}

	public void addEnvironmentVar(String name, double value) {
		envmap.put(name, new Double(value));
	}

	public void addEnvironmentVar(String name, Object value) {
		envmap.put(name, value);
	}

	public void removeEnvironmentVar(String name) {
		envmap.remove(name);
	}

	public Object getEnvironmentVar(String name) {
		return envmap.get(name);
	}

	public void addParameter(String key, String label, int type, Object defaultValue) {
		if (gatherParamPanel == null) {
			return;
		}
		gatherParamPanel.addParameter(key, label, type, defaultValue);
	}

	public boolean displayParameterGatherer(String title) {
		if (gatherParamPanel == null) {
			return false;
		}
		if (!gatherParamPanel.panelShown()) {
			int ans = JOptionPane.showConfirmDialog(null, gatherParamPanel, title,
				JOptionPane.OK_CANCEL_OPTION);
			if (ans == JOptionPane.CANCEL_OPTION) {
				gatherParamPanel.setShown(false);
				return false;
			}
			gatherParamPanel.setShown(true);
			gatherParamPanel.setParamsInState();
		}
		return true;
	}

	public GatherParamPanel getParamPanel() {
		return gatherParamPanel;
	}

	public Set<String> getEnvironmentNames() {
		return envmap.keySet();
	}
}
