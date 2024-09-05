package ghidra.pyghidra.interpreter;

import java.io.PrintWriter;

import ghidra.util.task.TaskMonitorAdapter;

final class InterpreterTaskMonitor extends TaskMonitorAdapter {

	private PrintWriter output = null;

	InterpreterTaskMonitor(PrintWriter stdOut) {
		output = stdOut;
	}

	@Override
	public void setMessage(String message) {
		output.println("<pyghidra-interactive>: " + message);
	}
}
