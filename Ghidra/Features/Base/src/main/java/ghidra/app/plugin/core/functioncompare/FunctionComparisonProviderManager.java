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
package ghidra.app.plugin.core.functioncompare;

import java.util.*;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * FunctionComparisonProviderManager allows a plugin to display function comparison panels.
 * It responds to program close events and closes any panels that have a function from the
 * closed program. It also updates the displays if needed due to an Undo.
 */
public class FunctionComparisonProviderManager implements FunctionComparisonProviderListener {

	private HashSet<FunctionComparisonProvider> functionComparisonProviders = new HashSet<>();
	private ProgramPlugin plugin;
	private PluginTool tool;

	/**
	 * Constructs a FunctionComparisonProviderManager.
	 * @param plugin the plugin that owns this manager.
	 */
	public FunctionComparisonProviderManager(ProgramPlugin plugin) {
		this.plugin = plugin;
		tool = plugin.getTool();
	}

	/**
	 * This will create a new function comparison panel with the specified functions available for 
	 * display in both the left and right side of the panel. Initially the function comparison panel 
	 * will display the first function in the left side and the second function in the right side of 
	 * the panel. If the manager already has a provider to display the specified functions it will 
	 * be brought to the front instead of creating a new panel.
	 * @param functions the functions that are used to populate both the left and right side
	 * of the function comparison panel.
	 * @return the FunctionComparisonProvider that is displaying these functions.
	 */
	public FunctionComparisonProvider showFunctionComparisonProvider(Function[] functions) {
		FunctionComparisonProvider functionComparisonProvider =
			findFunctionComparisonProvider(functions);
		if (functionComparisonProvider != null) {
			// If it is already displayed then bring it to the front.
			tool.toFront(functionComparisonProvider);
			return functionComparisonProvider;
		}
		FunctionComparisonProvider provider =
			new FunctionComparisonProvider(plugin, functions, this);
		functionComparisonProviders.add(provider);
		provider.setVisible(true);
		return provider;
	}

	/**
	 * This creates a new function comparison panel with the specified leftFunctions available for 
	 * display in the left side of the panel and the rightFunctions available for display in the right side.
	 * Initially the function comparison panel will display the first leftFunction and the first
	 * rightFunction. If the manager already has a provider to display the specified leftFunctions
	 * and rightFunctions it will be brought to the front instead of creating a new panel. 
	 * @param leftFunctions the functions that are used to populate the left side
	 * @param rightFunctions the functions that are used to populate the right side
	 * @return the FunctionComparisonProvider that is displaying these functions.
	 */
	public FunctionComparisonProvider showFunctionComparisonProvider(Function[] leftFunctions,
			Function[] rightFunctions) {
		FunctionComparisonProvider functionComparisonProvider =
			findFunctionComparisonProvider(leftFunctions, rightFunctions);
		if (functionComparisonProvider != null) {
			// If it is already displayed then bring it to the front.
			tool.toFront(functionComparisonProvider);
			return functionComparisonProvider;
		}
		FunctionComparisonProvider provider =
			new FunctionComparisonProvider(plugin, leftFunctions, rightFunctions, this);
		functionComparisonProviders.add(provider);
		provider.setVisible(true);
		return provider;
	}

	/**
	 * This creates a new function comparison panel with the specified left functions 
	 * available for display in the left side of the panel and a list of functions for the 
	 * right side for each function in the left.
	 * If the manager already has a provider to display the specified function map it will 
	 * be brought to the front instead of creating a new panel.
	 * @param functionMap map of the functions that are used to populate both the left and 
	 * right side of the function comparison panel.
	 * @return the FunctionComparisonProvider that is displaying these functions.
	 */
	public FunctionComparisonProvider showFunctionComparisonProvider(
			HashMap<Function, HashSet<Function>> functionMap) {
		FunctionComparisonProvider functionComparisonProvider =
			findFunctionComparisonProvider(functionMap);
		if (functionComparisonProvider != null) {
			// If it is already displayed then bring it to the front.
			tool.toFront(functionComparisonProvider);
			return functionComparisonProvider;
		}
		FunctionComparisonProvider provider =
			new FunctionComparisonProvider(plugin, functionMap, this);
		functionComparisonProviders.add(provider);
		provider.setVisible(true);
		return provider;
	}

	private FunctionComparisonProvider findFunctionComparisonProvider(Function[] functions) {
		for (FunctionComparisonProvider functionComparisonProvider : functionComparisonProviders) {
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			if (functionComparisonPanel instanceof MultiFunctionComparisonPanel) {
				MultiFunctionComparisonPanel multiPanel =
					(MultiFunctionComparisonPanel) functionComparisonPanel;
				if (multiPanel.matchesTheseFunctions(functions, functions)) {
					return functionComparisonProvider;
				}
			}
			else { // basic FunctionComparisonPanel
				Function[] panelFunctions = functionComparisonPanel.getFunctions();
				if (Arrays.equals(panelFunctions, functions)) {
					return functionComparisonProvider;
				}
			}
		}
		return null;
	}

	private FunctionComparisonProvider findFunctionComparisonProvider(Function[] functionsL,
			Function[] functionsR) {
		for (FunctionComparisonProvider functionComparisonProvider : functionComparisonProviders) {
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			if (!(functionComparisonPanel instanceof MultiFunctionComparisonPanel)) {
				continue;
			}
			MultiFunctionComparisonPanel multiPanel =
				(MultiFunctionComparisonPanel) functionComparisonPanel;
			if (multiPanel.matchesTheseFunctions(functionsL, functionsR)) {
				return functionComparisonProvider;
			}
		}
		return null;
	}

	private FunctionComparisonProvider findFunctionComparisonProvider(
			HashMap<Function, HashSet<Function>> functionMap) {

		for (FunctionComparisonProvider functionComparisonProvider : functionComparisonProviders) {
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			if (functionComparisonPanel instanceof MappedFunctionComparisonPanel) {
				MappedFunctionComparisonPanel mappedPanel =
					(MappedFunctionComparisonPanel) functionComparisonPanel;
				if (mappedPanel.matchesTheseFunctions(functionMap)) {
					return functionComparisonProvider;
				}
			}
		}
		return null;
	}

	@Override
	public void providerClosed(FunctionComparisonProvider provider) {
		functionComparisonProviders.remove(provider);
	}

	/**
	 * Closes all the function comparison providers that have a function from the indicated program.
	 * This method should be called when a program is closing.
	 * @param program the program whose function providers need to close.
	 */
	public void closeProviders(Program program) {
		// Get an array of the providers and loop over it to notify them. This is to prevent
		// causing a ConcurrentModificationException. If a provider closes due to the indicated 
		// program closing, this manager will get notified via the providerClosed method and 
		// remove that provider from the functionComparisonProviders hashset.
		FunctionComparisonProvider[] providers = functionComparisonProviders
			.toArray(new FunctionComparisonProvider[functionComparisonProviders.size()]);
		for (FunctionComparisonProvider functionComparisonProvider : providers) {
			functionComparisonProvider.programClosed(program); // Allow the provider to close itself.
		}
	}

	/**
	 * Cleans up since this manager is being disposed. All function comparison providers will
	 * close and be cleaned up.
	 */
	public void dispose() {
		for (FunctionComparisonProvider functionComparisonProvider : functionComparisonProviders) {
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			functionComparisonPanel.setVisible(false);
			functionComparisonPanel.dispose();
		}
		functionComparisonProviders.clear();
	}

	/**
	 * Called when there is an Undo/Redo. If a program is being restored, this will notify all the 
	 * function comparison providers. This allows them to refresh if they are showing a function 
	 * from the program.
	 * @param ev the event indicating if this is an Undo/Redo on a program.
	 */
	public void domainObjectRestored(DomainObjectChangedEvent ev) {
		for (DomainObjectChangeRecord domainObjectChangeRecord : ev) {
			int eventType = domainObjectChangeRecord.getEventType();
			if (eventType == DomainObject.DO_OBJECT_RESTORED) {
				Object source = ev.getSource();
				if (source instanceof Program) {
					Program program = (Program) source;
					for (FunctionComparisonProvider functionComparisonProvider : functionComparisonProviders) {
						functionComparisonProvider.programRestored(program);
					}
				}
			}
		}
	}
}
