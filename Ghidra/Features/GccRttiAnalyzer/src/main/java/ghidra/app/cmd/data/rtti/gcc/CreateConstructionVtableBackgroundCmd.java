package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.Msg;

public class CreateConstructionVtableBackgroundCmd extends AbstractCreateVtableBackgroundCmd {

	private static final String NAME = CreateConstructionVtableBackgroundCmd.class.getSimpleName();

	private TypeInfo parent;
	private TypeInfo child;

	private static final String PREFIX = "_ZTC";
	private static final String SEPARATOR = "_";

	public CreateConstructionVtableBackgroundCmd(VtableModel vtable, ClassTypeInfo child) {
		super(vtable, NAME);
		try {
			this.parent = vtable.getTypeInfo();
		} catch (InvalidDataTypeException e) {
			Msg.error(this, e);
		}
		this.child = child;
	}

	@Override
	protected String getSymbolName() {
		return VtableModel.CONSTRUCTION_SYMBOL_NAME;
	}

	@Override
	protected String getMangledString() throws InvalidDataTypeException {
		return PREFIX+child.getTypeName()+SEPARATOR+parent.getTypeName();
	}
}
