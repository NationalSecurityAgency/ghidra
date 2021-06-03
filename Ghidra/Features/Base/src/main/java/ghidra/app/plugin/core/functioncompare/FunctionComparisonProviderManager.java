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

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import docking.ComponentProviderActivationListener;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Provides access to all open {@link FunctionComparisonProvider comparison providers}
 * and allows users to do the following:
 * <li>create new providers</li>
 * <li>add comparisons to existing providers</li>
 * <li>remove comparisons</li>
 * <li>notify subscribers when providers are opened/closed</li>
 */
public class FunctionComparisonProviderManager implements FunctionComparisonProviderListener {

	private Set<FunctionComparisonProvider> providers = new CopyOnWriteArraySet<>();
	private Set<ComponentProviderActivationListener> listeners = new HashSet<>();
	private Plugin plugin;

	/**
	 * Constructor
	 * 
	 * @param plugin the parent plugin
	 */
	public FunctionComparisonProviderManager(Plugin plugin) {
		this.plugin = plugin;
	}

	@Override
	public void providerClosed(FunctionComparisonProvider provider) {
		providers.remove(provider);
		listeners.stream().forEach(l -> l.componentProviderDeactivated(provider));
	}

	@Override
	public void providerOpened(FunctionComparisonProvider provider) {
		listeners.stream().forEach(l -> l.componentProviderActivated(provider));
	}

	/**
	 * Creates a new comparison between the given set of functions
	 * 
	 * @param functions the functions to compare
	 * @return the new comparison provider
	 */
	public FunctionComparisonProvider compareFunctions(Set<Function> functions) {
		if (functions.isEmpty()) {
			return null;
		}
		FunctionComparisonProvider provider = new MultiFunctionComparisonProvider(plugin);
		provider.addToTool();
		provider.getModel().compareFunctions(functions);
		providers.add(provider);
		provider.setVisible(true);
		return provider;
	}

	/**
	 * Creates a new comparison comparison between two functions
	 * 
	 * @param source the source function
	 * @param target the target function
	 * @return the new comparison provider
	 */
	public FunctionComparisonProvider compareFunctions(Function source,
			Function target) {
		FunctionComparisonProvider provider = new MultiFunctionComparisonProvider(plugin);
		provider.addToTool();
		provider.getModel().compareFunctions(source, target);
		providers.add(provider);
		provider.setVisible(true);
		return provider;
	}

	/**
	 * Adds a set of functions to an existing comparison provider
	 * 
	 * @param functions the functions to compare
	 * @param provider the provider to add the functions to
	 */
	public void compareFunctions(Set<Function> functions, FunctionComparisonProvider provider) {
		if (functions.isEmpty() || provider == null) {
			return;
		}

		providers.add(provider);
		provider.setVisible(true);
		provider.getModel().compareFunctions(functions);
	}

	/**
	 * Adds the given functions to an existing comparison provider
	 * 
	 * @param source the source function
	 * @param target the target function
	 * @param provider the provider to add the functions to
	 */
	public void compareFunctions(Function source, Function target,
			FunctionComparisonProvider provider) {
		if (provider == null) {
			return;
		}

		providers.add(provider);
		provider.setVisible(true);
		provider.getModel().compareFunctions(source, target);
	}

	/**
	 * Removes a given function from all comparisons across all providers
	 * 
	 * @param function the function to remove
	 */
	public void removeFunction(Function function) {
		providers.stream().forEach(p -> p.getModel().removeFunction(function));
	}

	/**
	 * Removes a given function from a specified provider
	 * 
	 * @param function the function to remove
	 * @param provider the provider to remove the function from
	 */
	public void removeFunction(Function function, FunctionComparisonProvider provider) {
		if (provider == null) {
			return;
		}
		provider.getModel().removeFunction(function);
	}

	/**
	 * Registers subscribers who wish to know of provider activation status
	 * 
	 * @param listener the subscriber to register
	 */
	public void addProviderListener(ComponentProviderActivationListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes a subscriber who no longer wishes to receive provider activation
	 * events
	 * 
	 * @param listener the subscriber to remove
	 */
	public void removeProviderListener(ComponentProviderActivationListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Closes all the comparison providers that contain a function from 
	 * the given program
	 * 
	 * @param program the program whose function providers need to close
	 */
	public void closeProviders(Program program) {
		providers.stream().forEach(p -> p.programClosed(program));
	}

	/**
	 * Removes any comparisons that contain a function from the given program
	 * 
	 * @param program the program whose functions require removal
	 */
	public void removeFunctions(Program program) {
		providers.stream().forEach(p -> p.removeFunctions(program));
	}

	/**
	 * Cleans up all providers, setting them invisible and removing any 
	 * associated ui components (eg: tabs)
	 */
	public void dispose() {
		for (FunctionComparisonProvider provider : providers) {
			FunctionComparisonPanel panel = provider.getComponent();
			panel.setVisible(false);
			panel.dispose();
		}
		providers.clear();
	}

	/**
	 * Called when there is an Undo/Redo. If a program is being restored, this 
	 * will notify all the function comparison providers. This allows them to 
	 * refresh if they are showing a function from the program
	 * 
	 * @param ev the object changed event
	 */
	public void domainObjectRestored(DomainObjectChangedEvent ev) {
		for (DomainObjectChangeRecord domainObjectChangeRecord : ev) {
			int eventType = domainObjectChangeRecord.getEventType();
			if (eventType != DomainObject.DO_OBJECT_RESTORED) {
				return;
			}
			Object source = ev.getSource();
			if (source instanceof Program) {
				Program program = (Program) source;
				providers.stream().forEach(p -> p.programRestored(program));
			}
		}
	}
}
