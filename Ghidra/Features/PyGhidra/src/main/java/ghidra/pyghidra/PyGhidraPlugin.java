package ghidra.pyghidra;

import java.util.function.Consumer;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.pyghidra.interpreter.InterpreterGhidraScript;
import ghidra.pyghidra.interpreter.PyGhidraInterpreter;
import ghidra.util.exception.AssertException;

/**
 * This plugin provides the interactive Python interpreter.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "PyGhidra Interpreter",
	description = "Provides an interactive Python Interpreter that is tightly integrated with a loaded Ghidra program.",
	servicesRequired = { InterpreterPanelService.class }
)
//@formatter:on
public class PyGhidraPlugin extends ProgramPlugin {

	public static final String TITLE = "PyGhidra";
	private static Consumer<PyGhidraPlugin> initializer = null;

	public final InterpreterGhidraScript script = new InterpreterGhidraScript();
	public PyGhidraInterpreter interpreter;

	public PyGhidraPlugin(PluginTool tool) {
		super(tool);
		GhidraState state = new GhidraState(tool, tool.getProject(), null, null, null, null);
		// use the copy constructor so this state doesn't fire plugin events
		script.set(new GhidraState(state), null, null);
	}

	/**
	 * Sets the plugin's Python side initializer.<p>
	 * 
     * This method is for <b>internal use only</b> and is only public so it can be
     * called from Python.
	 * 
	 * @param initializer the Python side initializer
	 * @throws AssertException if the code completer has already been set
	 */
	public static void setInitializer(Consumer<PyGhidraPlugin> initializer) {
		if (PyGhidraPlugin.initializer != null) {
			throw new AssertException("PyGhidraPlugin initializer has already been set");
		}
		PyGhidraPlugin.initializer = initializer;
	}

	@Override
	public void init() {
		interpreter = new PyGhidraInterpreter(this, PyGhidraPlugin.initializer != null);
		if (initializer != null) {
			initializer.accept(this);
		}
	}

	@Override
	public void dispose() {
		interpreter.dispose();
		super.dispose();
	}

	@Override
	protected void programActivated(Program program) {
		script.setCurrentProgram(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		if (script.getCurrentProgram() == program) {
			script.setCurrentProgram(null);
		}
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		script.setCurrentLocation(location);
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		script.setCurrentSelection(selection);
	}

	@Override
	protected void highlightChanged(ProgramSelection highlight) {
		script.setCurrentHighlight(highlight);
	}
}
