package ghidra.pyhidra;

import java.io.*;
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
import ghidra.pyhidra.PythonFieldExposer.ExposedFields;
import ghidra.util.exception.AssertException;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GhidraScript} provider for native python3 scripts
 */
public final class PyhidraScriptProvider extends AbstractPythonScriptProvider {

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
		if (PyhidraScriptProvider.scriptRunner != null) {
			throw new AssertException("scriptRunner has already been set");
		}
		PyhidraScriptProvider.scriptRunner = scriptRunner;
	}

	@Override
	public String getDescription() {
		return PyhidraPlugin.TITLE;
	}

	@Override
	public String getRuntimeEnvironmentName() {
		return PyhidraPlugin.TITLE;
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws GhidraScriptLoadException {
		if (scriptRunner == null) {
			String msg = "Ghidra was not started with pyhidra. Python is not available";
			throw new GhidraScriptLoadException(msg);
		}
		GhidraScript script = SystemUtilities.isInHeadlessMode() ? new PyhidraHeadlessScript()
				: new PyhidraGhidraScript();
		script.setSourceFile(sourceFile);
		return script;
	}

	@ExposedFields(
		exposer = PyhidraGhidraScript.ExposedField.class,
		names = {
			"currentAddress", "currentLocation", "currentSelection",
			"currentHighlight", "currentProgram", "monitor",
			"potentialPropertiesFileLocs", "propertiesFileParams",
			"sourceFile", "state", "writer"
		},
		types = {
			Address.class, ProgramLocation.class, ProgramSelection.class,
			ProgramSelection.class, Program.class, TaskMonitor.class,
			List.class, GhidraScriptProperties.class,
			ResourceFile.class, GhidraState.class, PrintWriter.class
		}
	)
	final static class PyhidraGhidraScript extends GhidraScript
			implements PythonFieldExposer {

		@Override
		public void run() {
			scriptRunner.accept(this);
		}

		/**
		 * Helper inner class that can create a {@link MethodHandles.Lookup}
		 * that can access the protected fields of the {@link GhidraScript}
		 */
		private static class ExposedField extends PythonFieldExposer.ExposedField {
			public ExposedField(String name, Class<?> type) {
				super(MethodHandles.lookup().in(PyhidraGhidraScript.class), name, type);
			}
		}
	}

	@ExposedFields(
		exposer = PyhidraHeadlessScript.ExposedField.class,
		names = {
			"currentAddress", "currentLocation", "currentSelection",
			"currentHighlight", "currentProgram", "monitor",
			"potentialPropertiesFileLocs", "propertiesFileParams",
			"sourceFile", "state", "writer"
		},
		types = {
			Address.class, ProgramLocation.class, ProgramSelection.class,
			ProgramSelection.class, Program.class, TaskMonitor.class,
			List.class, GhidraScriptProperties.class,
			ResourceFile.class, GhidraState.class, PrintWriter.class
		}
	)
	final static class PyhidraHeadlessScript extends HeadlessScript
			implements PythonFieldExposer {

		@Override
		public void run() {
			scriptRunner.accept(this);
		}

		/**
		 * Helper inner class that can create a {@link MethodHandles.Lookup}
		 * that can access the protected fields of the {@link GhidraScript}
		 */
		private static class ExposedField extends PythonFieldExposer.ExposedField {
			public ExposedField(String name, Class<?> type) {
				super(MethodHandles.lookup().in(PyhidraHeadlessScript.class), name, type);
			}
		}
	}
}
