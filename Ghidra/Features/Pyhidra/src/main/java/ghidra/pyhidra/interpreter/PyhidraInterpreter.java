package ghidra.pyhidra.interpreter;

import java.io.PrintWriter;
import java.util.List;

import javax.swing.Icon;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.pyhidra.PyhidraPlugin;
import ghidra.util.Disposable;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

/**
 * The pyhidra interpreter connection
 */
public final class PyhidraInterpreter implements Disposable, InterpreterConnection {

    private PyhidraConsole pyhidraConsole = null;
    public final InterpreterConsole console;

    public PyhidraInterpreter(PyhidraPlugin plugin, boolean isPythonAvailable) {
        InterpreterPanelService service =
            plugin.getTool().getService(InterpreterPanelService.class);
        console = service.createInterpreterPanel(this, false);
        if (!isPythonAvailable) {
            console.addFirstActivationCallback(this::unavailableCallback);
        }
    }

    @Override
    public void dispose() {
        if (pyhidraConsole != null) {
            pyhidraConsole.dispose();
        }
        console.dispose();
    }

    @Override
    public Icon getIcon() {
        return ResourceManager.loadImage("images/python.png");
    }

    @Override
    public String getTitle() {
        return PyhidraPlugin.TITLE;
    }

    @Override
    public List<CodeCompletion> getCompletions(String cmd) {
        throw new AssertException("Unreachable, unimplemented and deprecated method");
    }

    @Override
    public List<CodeCompletion> getCompletions(String cmd, int caretPos) {
        if (pyhidraConsole == null) {
            return List.of();
        }
        return pyhidraConsole.getCompletions(cmd, caretPos);
    }

    private void unavailableCallback() {
        console.setInputPermitted(false);
        PrintWriter out = console.getOutWriter();
        out.println("Ghidra was not started with pyhidra. Python is not available.");
    }

    /**
     * Initializes the interpreter with the provided PyhidraConsole.
     * 
     * This method is for <b>internal use only</b> and is only public so it can be
     * called from Python.
     * 
     * @param pythonSideConsole the python side console
     * @throws AssertException if the interpreter has already been initialized
     */
    public void init(PyhidraConsole pythonSideConsole) {
        if (pyhidraConsole != null) {
            throw new AssertException("the interpreter has already been initialized");
        }
        pyhidraConsole = pythonSideConsole;
        console.addFirstActivationCallback(pyhidraConsole::restart);
        console.addAction(new CancelAction(pyhidraConsole));
        console.addAction(new ResetAction(pyhidraConsole));
    }
}
