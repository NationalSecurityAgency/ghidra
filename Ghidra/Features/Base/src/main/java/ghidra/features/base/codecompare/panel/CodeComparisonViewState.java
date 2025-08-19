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
import java.util.Map.Entry;

import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;

/**
 * A state object to save settings each type of comparison view known by the system.  This class
 * is meant to be used to allow user settings to be applied to each new comparison widget that is 
 * created.   Also, the class allows the tool to save those settings when the tool is saved.
 * <p>
 * When a comparison provider updates its save state object, it should call 
 * {@link PluginTool#setConfigChanged(boolean)} so that tool knows there are settings to be saved.
 */
public class CodeComparisonViewState {

	private static final String FUNCTION_COMPARISON_STATES = "CodeComparisonStates";

	private Map<Class<? extends CodeComparisonView>, SaveState> states = new HashMap<>();

	public SaveState getSaveState(Class<? extends CodeComparisonView> clazz) {
		return states.computeIfAbsent(clazz, this::createSaveState);
	}

	private SaveState createSaveState(Class<? extends CodeComparisonView> clazz) {
		return new SaveState();
	}

	/**
	 * Called by the tool to write the panels' saved states into the tools save state
	 * @param saveState the tool's save state
	 */
	public void writeConfigState(SaveState saveState) {
		Set<Entry<Class<? extends CodeComparisonView>, SaveState>> entries = states.entrySet();
		SaveState classStates = new SaveState();
		for (Entry<Class<? extends CodeComparisonView>, SaveState> entry : entries) {
			Class<? extends CodeComparisonView> clazz = entry.getKey();
			SaveState subState = entry.getValue();
			classStates.putSaveState(clazz.getName(), subState);
		}

		saveState.putSaveState(FUNCTION_COMPARISON_STATES, classStates);
	}

	/**
	 * Called by the tool to load saved state for the comparison providers
	 * @param saveState the tool's state 
	 */
	public void readConfigState(SaveState saveState) {

		SaveState classStates = saveState.getSaveState(FUNCTION_COMPARISON_STATES);
		if (classStates == null) {
			return;
		}

		String[] names = classStates.getNames();
		for (String className : names) {
			try {
				@SuppressWarnings("unchecked")
				Class<? extends CodeComparisonView> clazz =
					(Class<? extends CodeComparisonView>) Class.forName(className);
				SaveState classState = classStates.getSaveState(className);
				states.put(clazz, classState);
			}
			catch (ClassNotFoundException e) {
				// ignore
			}
		}
	}
}
