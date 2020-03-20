package ghidra.app.script.osgi;

import ghidra.util.exception.UsrException;

public class OSGiException extends UsrException {
	public OSGiException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public OSGiException(String msg) {
		super(msg);
	}
}
