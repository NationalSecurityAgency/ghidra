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
package ghidra.debug.api.action;

import java.util.*;

import javax.swing.Icon;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvent;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An interface for specifying how to automatically map dynamic memory to static memory.
 */
public interface AutoMapSpec extends ExtensionPoint {
	class Private {
		private final Map<String, AutoMapSpec> specsByName = new TreeMap<>();
		private final ChangeListener classListener = this::classesChanged;

		private Private() {
			ClassSearcher.addChangeListener(classListener);
			classesChanged(null);
		}

		private synchronized void classesChanged(ChangeEvent evt) {
			InstanceUtils.collectUniqueInstances(AutoMapSpec.class, specsByName,
				AutoMapSpec::getConfigName);
		}
	}

	Private PRIVATE = new Private();

	public static class AutoMapSpecConfigFieldCodec implements ConfigFieldCodec<AutoMapSpec> {
		@Override
		public AutoMapSpec read(SaveState state, String name,
				AutoMapSpec current) {
			String specName = state.getString(name, null);
			return fromConfigName(specName);
		}

		@Override
		public void write(SaveState state, String name, AutoMapSpec value) {
			state.putString(name, value.getConfigName());
		}
	}

	static AutoMapSpec fromConfigName(String name) {
		synchronized (PRIVATE) {
			return PRIVATE.specsByName.get(name);
		}
	}

	static Map<String, AutoMapSpec> allSpecs() {
		synchronized (PRIVATE) {
			return new TreeMap<>(PRIVATE.specsByName);
		}
	}

	String getConfigName();

	String getMenuName();

	Icon getMenuIcon();

	Collection<TraceEvent<?, ?>> getChangeTypes();

	boolean objectHasType(TraceObjectValue value);

	String getInfoForObjects(Trace trace, long snap);

	default boolean hasTask() {
		return true;
	}

	default String getTaskTitle() {
		return getMenuName();
	}

	default void runTask(PluginTool tool, Trace trace, long snap) {
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		ProgramManager programManager = tool.getService(ProgramManager.class);
		if (mappingService == null || programManager == null) {
			return;
		}
		BackgroundCommand<Trace> cmd = new BackgroundCommand<>(getTaskTitle(), true, true, false) {
			@Override
			public boolean applyTo(Trace trace, TaskMonitor monitor) {
				try {
					performMapping(mappingService, trace, snap, programManager, monitor);
					return true;
				}
				catch (CancelledException e) {
					return false;
				}
			}
		};
		tool.executeBackgroundCommand(cmd, trace);
	}

	List<Program> programs(ProgramManager programManager);

	/**
	 * Perform the actual mapping
	 * 
	 * @param mappingService the mapping service
	 * @param trace the trace
	 * @param snap the snap
	 * @param programs the programs to consider
	 * @param monitor a task monitor
	 * @return true if any mappings were added
	 * @throws CancelledException if the task monitor cancelled the task
	 */
	boolean performMapping(DebuggerStaticMappingService mappingService, Trace trace, long snap,
			List<Program> programs, TaskMonitor monitor) throws CancelledException;

	/**
	 * Perform the actual mapping
	 * 
	 * @param mappingService the mapping service
	 * @param trace the trace
	 * @param snap the snap
	 * @param programManager the program manager
	 * @param monitor a task monitor
	 * @return true if any mappings were added
	 * @throws CancelledException if the task monitor cancelled the task
	 */
	default boolean performMapping(DebuggerStaticMappingService mappingService, Trace trace,
			long snap, ProgramManager programManager, TaskMonitor monitor)
			throws CancelledException {
		return performMapping(mappingService, trace, snap, programs(programManager), monitor);
	}
}
