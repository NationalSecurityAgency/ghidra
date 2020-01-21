package ghidra.app.util.bin.format.stabs.types;

import ghidra.app.util.bin.format.stabs.StabsFile;
import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsSymbolDescriptor;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

/**
 * Abstract Base Class for StabTypeDescriptor Implementations
 */
abstract class AbstractStabsTypeDescriptor implements StabsTypeDescriptor {

	protected final String stab;
	protected final StabsFile file;
	protected final Program program;
	protected final DataTypeManager dtm;
	protected CategoryPath path;
	protected final StabsSymbolDescriptor symbol;

	protected AbstractStabsTypeDescriptor(StabsSymbolDescriptor token, String stab) {
		this.symbol = token;
		this.stab = stab;
		this.file = token.getFile();
		this.program = file.getProgram();
		this.dtm = program.getDataTypeManager();
		this.path = file.getCategoryPath();
	}

	protected AbstractStabsTypeDescriptor(StabsTypeDescriptor descriptor, String stab) {
		this(descriptor.getSymbolDescriptor(), stab);
	}

	@Override
	public String getStab() {
		return stab;
	}

	@Override
	public StabsSymbolDescriptor getSymbolDescriptor() {
		return symbol;
	}

	protected StabsParseException getError() {
		return new StabsParseException(symbol.getName(), stab);
	}

}
