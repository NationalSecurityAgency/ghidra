package ghidra.pyhidra.interpreter;

import java.util.List;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.util.Disposable;

/**
 * Console interface providing only the methods which need to be implemented in Python.
 * 
 * This interface is for <b>internal use only</b> and is only public so it can be
 * implemented in Python.
 */
public interface PyhidraConsole extends Disposable {

    /**
     * Generates code completions for the pyhidra interpreter
     * 
     * @param cmd The command to get code completions for
     * @param caretPos The position of the caret in the input string 'cmd'.
     *                 It should satisfy the constraint {@literal "0 <= caretPos <= cmd.length()"}
     * @return A {@link List} of {@link CodeCompletion code completions} for the given command
     * @see InterpreterConnection InterpreterConnection.getCompletions(String, int)
     */
    List<CodeCompletion> getCompletions(String cmd, int caretPos);

    /**
     * Restarts the pyhidra console
     */
    void restart();
    
    /**
     * Interrupts the code running in the pyhidra console
     */
    void interrupt();
}
