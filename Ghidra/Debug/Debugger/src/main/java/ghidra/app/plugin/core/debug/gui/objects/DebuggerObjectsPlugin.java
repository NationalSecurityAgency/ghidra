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
package ghidra.app.plugin.core.debug.gui.objects;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.services.*;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.datastruct.CollectionChangeListener;

@PluginInfo(
	shortDescription = "Debugger objects manager",
	description = "GUI to manage connections to external debuggers and trace recording",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramActivatedPluginEvent.class, // for default launch executable path
		ProgramOpenedPluginEvent.class,
		ProgramSelectionPluginEvent.class,
		TraceActivatedPluginEvent.class,
		TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class,
		ModelActivatedPluginEvent.class,
	},
	servicesProvided = { ObjectUpdateService.class },
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerModelService.class,
		DebuggerInterpreterService.class,
	})
public class DebuggerObjectsPlugin extends AbstractDebuggerPlugin
		implements ObjectUpdateService, CollectionChangeListener<DebuggerObjectModel> {

	static String TITLE_PROVIDER_TARGETS = "Debugger Objects";

	@AutoServiceConsumed
	protected DebuggerInterpreterService interpreterService;
	@AutoServiceConsumed
	public DebuggerModelService modelService;

	private List<DebuggerObjectsProvider> providers = new ArrayList<>();
	private boolean firstPass = true;
	private Program activeProgram;
	// Because there's no "primary" provider, save a copy of read config state to apply to new providers 
	private SaveState copiedSaveState = new SaveState();

	public DebuggerObjectsPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		try {
			ObjectContainer init = new ObjectContainer(null, null);
			DebuggerObjectsProvider p = new DebuggerObjectsProvider(this, null, init, true);
			init.propagateProvider(p);
			p.update(init);
			p.setVisible(true);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		super.init();
	}

	@Override
	protected void dispose() {
		providers.get(0).setVisible(true);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent ev = (TraceOpenedPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.traceOpened(ev.getTrace());
			}
		}
		else if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.traceActivated(ev.getActiveCoordinates());
			}
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.traceClosed(ev.getTrace());
			}
		}
		else if (event instanceof ModelActivatedPluginEvent) {
			ModelActivatedPluginEvent ev = (ModelActivatedPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.modelActivated(ev.getActiveModel());
			}
		}
		else if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.setProgram(ev.getActiveProgram());
			}
		}
		else if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent ev = (ProgramOpenedPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.setProgram(ev.getProgram());
			}
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelectionPluginEvent ev = (ProgramSelectionPluginEvent) event;
			for (DebuggerObjectsProvider provider : providers) {
				provider.setProgram(ev.getProgram());
			}
		}
	}

	public void addProvider(DebuggerObjectsProvider provider) {
		providers.add(provider);
	}

	@Override
	public void fireObjectUpdated(ObjectContainer object) {
		final ObjectUpdatedEvent event = new ObjectUpdatedEvent(object);

		// distribute selection within Ghidra tool
		Runnable r = () -> firePluginEvent(event);
		SwingUtilities.invokeLater(r);
	}

	public void showConsole(TargetInterpreter interpreter) {
		Swing.runIfSwingOrRunLater(() -> {
			interpreterService.showConsole(interpreter);
		});
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeModelsChangedListener(this);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addModelsChangedListener(this);
		}
	}

	class ProviderRunnable implements Runnable {
		private DebuggerObjectsPlugin plugin;
		private DebuggerObjectModel model;

		ProviderRunnable(DebuggerObjectsPlugin p, DebuggerObjectModel m) {
			this.plugin = p;
			this.model = m;
		}

		@Override
		public void run() {
			try {
				writeConfigState(copiedSaveState);
				ObjectContainer container = new ObjectContainer(null, null);
				DebuggerObjectsProvider p =
					new DebuggerObjectsProvider(plugin, model, container, true);
				p.readConfigState(copiedSaveState);
				container.propagateProvider(p);
				p.update(container);
				p.refresh();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public void elementAdded(DebuggerObjectModel model) {
		DebuggerObjectsProvider top = providers.get(providers.size() - 1);
		DebuggerObjectModel existingModel = top.getModel();
		if (existingModel == null) {
			top.setModel(model);
		}
		else {
			SwingUtilities.invokeLater(new ProviderRunnable(this, model));
		}
	}

	@Override
	public void elementRemoved(DebuggerObjectModel model) {
		List<DebuggerObjectsProvider> toRemove = new ArrayList<>();
		for (DebuggerObjectsProvider p : providers) {
			if (model.equals(p.getModel())) {
				tool.removeComponentProvider(p);
				toRemove.add(p);
			}
		}
		for (DebuggerObjectsProvider p : toRemove) {
			providers.remove(p);
		}
		if (providers.size() == 0) {
			Swing.runIfSwingOrRunLater(() -> {
				init();
			});
		}
	}

	@Override
	public void elementModified(DebuggerObjectModel model) {
		System.err.println("modelModified " + model);
	}

	public void setFocus(TargetObject object, TargetObject focused) {
		for (DebuggerObjectsProvider p : providers) {
			p.setFocus(object, focused);
		}
	}

	public Program getActiveProgram() {
		return activeProgram;
	}

	public void setActiveProgram(Program program) {
		this.activeProgram = program;
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		if (providers.isEmpty()) {
			return;
		}
		providers.get(0).writeConfigState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		copiedSaveState = new SaveState(saveState.saveToXml());
		if (providers.isEmpty()) {
			return;
		}
		providers.get(0).readConfigState(saveState);
	}
}
