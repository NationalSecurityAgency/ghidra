package ghidra.app.cmd.data.rtti.gcc;

import ghidra.app.cmd.data.rtti.TypeInfo;

public class CreateVtableBackgroundCmd extends AbstractCreateVtableBackgroundCmd {

    private static final String NAME = CreateVtableBackgroundCmd.class.getSimpleName();

    private static final String SYMBOL_NAME = "vtable";

    private TypeInfo type;

    public CreateVtableBackgroundCmd(VtableModel vtable) {
        super(vtable, NAME);
        this.type = vtable.getTypeInfo();
    }

    @Override
    protected String getSymbolName() {
        return SYMBOL_NAME;
    }

    @Override
    protected String getMangledString() {
        return VtableModel.MANGLED_PREFIX+type.getTypeName();
    }
}
