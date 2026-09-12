package ghidra.app.util.bin.format.stabs;

@SuppressWarnings("serial")
public final class StabsParseException extends Exception {

	public StabsParseException(String name, String stab) {
		super(String.format(
			"The stab type for %s failed to be parsed.\n%s", name, stab));
	}

	public StabsParseException(String name, String stab, Throwable t) {
		super(String.format(
			"The stab type for %s failed to be parsed.\n%s", name, stab), t);
	}
}
