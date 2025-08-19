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
package ghidra.features.base.codecompare.panel;

import java.util.*;

import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import utility.function.Callback;

/**
 * An object to share config state between providers and all views within those providers.
 * <p>
 * When a comparison provider updates its save state object, it should call 
 * {@link PluginTool#setConfigChanged(boolean)} so that tool knows there are settings to be saved.
 */
public class FunctionComparisonState {

	private static final String PROVIDER_SAVE_STATE_NAME = "FunctionComparison";

	private SaveState panelState = new SaveState();
	private CodeComparisonViewState comparisonState = new CodeComparisonViewState();

	private PluginTool tool;

	private List<Callback> updateCallbacks = new ArrayList<>();

	public FunctionComparisonState(PluginTool tool) {
		this.tool = tool;
	}

	/**
	 * Returns the state object for the provider
	 * @return the state object for the provider
	 */
	public SaveState getPanelState() {
		return panelState;
	}

	/**
	 * Returns the save state object for the views that live inside a provider
	 * @return the state
	 */
	public CodeComparisonViewState getViewState() {
		return comparisonState;
	}

	/**
	 * Signals to the tool that there are changes to the config state that can be saved.
	 */
	public void setChanged() {
		tool.setConfigChanged(true);
	}

	public void writeConfigState(SaveState saveState) {
		saveState.putSaveState(PROVIDER_SAVE_STATE_NAME, panelState);
		comparisonState.writeConfigState(saveState);
	}

	public void readConfigState(SaveState saveState) {
		SaveState restoredPanelState = saveState.getSaveState(PROVIDER_SAVE_STATE_NAME);
		if (restoredPanelState != null) {
			panelState = restoredPanelState;
		}

		comparisonState.readConfigState(saveState);
		updateCallbacks.forEach(Callback::call);
	}

	/**
	 * Adds a callback to this state that is notified when this state changes.
	 * @param callback the callback
	 */
	public void addUpdateCallback(Callback callback) {
		updateCallbacks.add(Objects.requireNonNull(callback));
	}
}
