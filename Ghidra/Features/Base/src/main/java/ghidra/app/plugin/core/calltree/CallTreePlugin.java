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
package ghidra.app.plugin.core.calltree;

import java.util.*;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.FunctionSupplierContext;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.StringUtilities;
import resources.Icons;
import util.CollectionUtils;

/**
 * Assuming a function <b>foo</b>, this plugin will show:
 *  1) all callers of <b>foo</b> 
 *  2) all functions which reference <b>foo</b>
 *  3) all callees of <b>foo</b>
 *  4) all functions referenced by <b>foo</b>. 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Call Trees Plugin",
	description = "This plugin shows incoming and outgoing calls and function references " +
		    "for a given function foo. More specifically, one tree of the plugin will show all " +
			"callers and function referring to foo and the other tree of the plugin will show " + 
		    "all calls and references to functions made by foo."
)
//@formatter:on
public class CallTreePlugin extends ProgramPlugin {

	static final Icon PROVIDER_ICON = Icons.ARROW_DOWN_RIGHT_ICON;

	private List<CallTreeProvider> providers = new ArrayList<>();
	private DockingAction showCallTreeFromMenuAction;
	private CallTreeProvider primaryProvider;

	public CallTreePlugin(PluginTool tool) {
		super(tool);

		createActions();
		primaryProvider = new CallTreeProvider(this, true);
		providers.add(primaryProvider);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		for (CallTreeProvider provider : providers) {
			provider.setLocation(loc);
		}
	}

	@Override
	protected void programActivated(Program program) {
		for (CallTreeProvider provider : providers) {
			provider.programActivated(program);
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		for (CallTreeProvider provider : providers) {
			provider.programDeactivated(program);
		}
	}

	@Override
	protected void programClosed(Program program) {
		for (CallTreeProvider provider : providers) {
			provider.programClosed(program);
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		primaryProvider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		primaryProvider.writeConfigState(saveState);
	}

	@Override
	protected void dispose() {
		List<CallTreeProvider> copy = new ArrayList<>(providers);
		for (CallTreeProvider provider : copy) {
			removeProvider(provider);
		}
	}

	private CallTreeProvider findTransientProviderForLocation(Function function) {
		for (CallTreeProvider provider : providers) {
			if (!provider.isTransient()) {
				continue;
			}

			if (provider.isShowingFunction(function)) {
				return provider;
			}
		}
		return null;
	}

	// Used by tests to find providers by location
	CallTreeProvider findTransientProviderForLocation(ProgramLocation location) {
		for (CallTreeProvider provider : providers) {
			if (!provider.isTransient()) {
				continue;
			}

			if (provider.isShowingLocation(location)) {
				return provider;
			}
		}
		return null;
	}

	private void createActions() {

		// use the name of the provider so that the shared key binding data will get used
		String actionName = "Static Function Call Trees";
		String group = "ShowReferencesTo";
		showCallTreeFromMenuAction = new DockingAction(actionName, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Function f = getFunction(context);
				showNewCallTree(f);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Function f = getFunction(context);
				if (f == null) {
					return false;
				}

				String menuText = "Show Call Trees for " + f.getName();
				String trimmedMenuText = StringUtilities.trim(menuText, 50);

				setPopupMenuData(new MenuData(
					new String[] { "References", trimmedMenuText }, PROVIDER_ICON, group));
				return true;
			}
		};

		showCallTreeFromMenuAction.setPopupMenuData(new MenuData(
			new String[] { "References", "Show Call Trees" }, PROVIDER_ICON, group));
		showCallTreeFromMenuAction
				.setHelpLocation(new HelpLocation("CallTreePlugin", "Call_Tree_Plugin"));
		showCallTreeFromMenuAction.setDescription("Shows the Function Call Trees window for the " +
			"item under the cursor.  The new window will not change along with the Listing cursor.");
		tool.addAction(showCallTreeFromMenuAction);
	}

	private Function getFunction(ActionContext context) {

		if (context instanceof ListingActionContext) {
			//
			// Unusual Code: We know that the ListingActionContext is a FunctionSupplierContext. 
			// We also know that this context does not report the current function as specifically
			// as we would like.  So, handle this case ourselves.  The fall-through case will allow
			// this plugin to work in other places like the Decompiler or the Functions window.
			//
			return getFunction(currentLocation);
		}

		if (context instanceof FunctionSupplierContext functionContext) {
			if (functionContext.hasFunctions()) {
				Set<Function> functions = functionContext.getFunctions();
				return CollectionUtils.any(functions);
			}
		}

		return getFunction(currentLocation);
	}

	private void createAndShowProvider(Function function) {
		CallTreeProvider provider = new CallTreeProvider(this, false);

		CallTreeOptions callTreeOptions = primaryProvider.getCallTreeOptions();
		provider.setCallTreeOptions(callTreeOptions);

		providers.add(provider);
		provider.initialize(currentProgram, function);
		tool.showComponentProvider(provider, true);
	}

	CallTreeProvider getPrimaryProvider() {
		return primaryProvider;
	}

	DockingAction getShowCallTreeFromMenuAction() {
		return showCallTreeFromMenuAction;
	}

	ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	void removeProvider(CallTreeProvider provider) {
		if (!providers.contains(provider)) {
			// already been removed (this sometimes happens twice, as this happens when providers
			// are closed by the user and when they are removed from the tool due to disposal)
			return;
		}

		providers.remove(provider);
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

	void showNewCallTree(Function function) {
		if (currentProgram == null) {
			return; // no program; cannot show tool
		}

		CallTreeProvider provider = findTransientProviderForLocation(function);
		if (provider != null) {
			tool.showComponentProvider(provider, true);
			return;
		}

		createAndShowProvider(function);
	}

	private Function getFunction(ProgramLocation location) {
		if (location == null) {
			return null;
		}
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Address address = location.getAddress();
		Function destinationFunction = getReferencedFunction(address);
		if (destinationFunction != null) {
			return destinationFunction;
		}
		return functionManager.getFunctionContaining(address);
	}

	Function getReferencedFunction(Address address) {
		// maybe we point to another function?
		FunctionManager functionManager = currentProgram.getFunctionManager();
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference[] references = referenceManager.getReferencesFrom(address);
		for (Reference reference : references) {
			Address toAddress = reference.getToAddress();
			Function toFunction = functionManager.getFunctionAt(toAddress);
			if (toFunction != null) {
				return toFunction;
			}
		}
		return null;
	}
}
