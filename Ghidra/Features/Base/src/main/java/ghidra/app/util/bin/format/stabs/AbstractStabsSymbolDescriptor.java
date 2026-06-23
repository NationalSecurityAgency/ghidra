package ghidra.app.util.bin.format.stabs;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;

/**
 * Abstract Base Class for StabSymbolDescriptor Implementations
 */
public abstract class AbstractStabsSymbolDescriptor implements StabsSymbolDescriptor {

	protected final String stab;
	protected final String name;
	protected final char descriptor;
	protected final StabsFile file;
	protected final DataTypeManager dtm;
	protected final CategoryPath path;
	private int anonCount = 0;

	AbstractStabsSymbolDescriptor(String stab, StabsFile file) {
		this.name = StabsParser.getNameFromStab(stab);
		this.stab = stab;
		this.file = file;
		this.dtm = file.getProgram().getDataTypeManager();
		this.path = file.getCategoryPath();
		this.descriptor = stab.charAt(name.length()+1);
	}

	protected String getTypeSubStab() {
		int index = stab.indexOf('=');
		if (index != -1) {
			return stab.substring(index+1);
		}
		index = stab.indexOf('(');
		if (index != -1) {
			return stab.substring(index);
		}
		return stab.substring(name.length()+2);
	}

	protected StabsParseException getError() {
		return new StabsParseException(getName(), stab);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getStab() {
		return stab;
	}

	@Override
	public final StabsFile getFile() {
		return file;
	}

	@Override
	public StabsTypeDescriptor getTypeInformation() {
		//default case for having no type information
		return null;
	}

	/**
	 * Gets the next available number for an anonymous inner type
	 * @return the next available number
	 */
	public int getNextAnonCount() {
		return anonCount++;
	}
}
