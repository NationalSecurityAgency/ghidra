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
package ghidra.pyghidra;

import java.io.PrintWriter;
import java.lang.invoke.MethodHandles;
import java.util.List;
import java.util.function.Consumer;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.pyghidra.PythonFieldExposer.ExposedFields;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GhidraScript} provider for native python3 scripts
 */
@ExtensionPointProperties(priority = 1000) // Enforce high priority so PyGhidra is the default Python provider
public final class PyGhidraScriptProvider extends AbstractPythonScriptProvider {

	private static Consumer<GhidraScript> scriptRunner = null;

	/**
	 * Sets the Python side script runner.
	 * 
	 * This method is for <b>internal use only</b> and is only public so it can be
	 * called from Python.
	 * 
	 * @param scriptRunner the Python side script runner
	 * @throws AssertException if the script runner has already been set
	 */
	public static void setScriptRunner(Consumer<GhidraScript> scriptRunner) {
		if (PyGhidraScriptProvider.scriptRunner != null) {
			throw new AssertException("scriptRunner has already been set");
		}
		PyGhidraScriptProvider.scriptRunner = scriptRunner;
	}

	@Override
	public String getDescription() {
		return PyGhidraPlugin.TITLE;
	}

	@Override
	public String getRuntimeEnvironmentName() {
		return PyGhidraPlugin.TITLE;
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws GhidraScriptLoadException {
		if (scriptRunner == null) {
			String msg = "Ghidra was not started with PyGhidra. Python is not available";
			throw new GhidraScriptLoadException(msg);
		}
		GhidraScript script = SystemUtilities.isInHeadlessMode() ? new PyGhidraHeadlessScript()
				: new PyGhidraGhidraScript();
		script.setSourceFile(sourceFile);
		return script;
	}

	@ExposedFields(
		exposer = PyGhidraGhidraScript.ExposedField.class,
		names = {
			"currentAddress", "currentLocation", "currentSelection",
			"currentHighlight", "currentProgram", "monitor",
			"potentialPropertiesFileLocs", "propertiesFileParams",
			"sourceFile", "state", "writer", "errorWriter"
		},
		types = {
			Address.class, ProgramLocation.class, ProgramSelection.class,
			ProgramSelection.class, Program.class, TaskMonitor.class,
			List.class, GhidraScriptProperties.class,
			ResourceFile.class, GhidraState.class, PrintWriter.class, PrintWriter.class
		}
	)
	final static class PyGhidraGhidraScript extends GhidraScript
			implements PythonFieldExposer {

		@Override
		public void run() {
			scriptRunner.accept(this);
		}

		/**
		 * Helper inner class that can create a {@link java.lang.invoke.MethodHandles.Lookup}
		 * that can access the protected fields of the {@link GhidraScript}
		 */
		private static class ExposedField extends PythonFieldExposer.ExposedField {
			public ExposedField(String name, Class<?> type) {
				super(MethodHandles.lookup().in(PyGhidraGhidraScript.class), name, type);
			}
		}
	}

	@ExposedFields(
		exposer = PyGhidraHeadlessScript.ExposedField.class,
		names = {
			"currentAddress", "currentLocation", "currentSelection",
			"currentHighlight", "currentProgram", "monitor",
			"potentialPropertiesFileLocs", "propertiesFileParams",
			"sourceFile", "state", "writer", "errorWriter"
		},
		types = {
			Address.class, ProgramLocation.class, ProgramSelection.class,
			ProgramSelection.class, Program.class, TaskMonitor.class,
			List.class, GhidraScriptProperties.class,
			ResourceFile.class, GhidraState.class, PrintWriter.class, PrintWriter.class
		}
	)
	final static class PyGhidraHeadlessScript extends HeadlessScript
			implements PythonFieldExposer {

		@Override
		public void run() {
			scriptRunner.accept(this);
		}

		/**
		 * Helper inner class that can create a {@link java.lang.invoke.MethodHandles.Lookup}
		 * that can access the protected fields of the {@link GhidraScript}
		 */
		private static class ExposedField extends PythonFieldExposer.ExposedField {
			public ExposedField(String name, Class<?> type) {
				super(MethodHandles.lookup().in(PyGhidraHeadlessScript.class), name, type);
			}
		}
	}
}
