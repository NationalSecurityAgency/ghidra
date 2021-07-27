package ghidra.pcode.emu;

import ghidra.program.model.address.AddressSpace;

public class BytesPcodeThread extends AbstractModifiedPcodeThread<byte[]> {
	public BytesPcodeThread(String name, AbstractPcodeMachine<byte[]> machine) {
		super(name, machine);
	}

	@Override
	protected int getBytesChunk(byte[] res, AddressSpace spc, long off, int size,
			boolean stopOnUnintialized) {
		byte[] var = state.getVar(spc, off, size, true);
		System.arraycopy(var, 0, res, 0, var.length);
		return var.length;
	}

	@Override
	protected void setBytesChunk(byte[] val, AddressSpace spc, long off, int size) {
		state.setVar(spc, off, size, true, val);
	}
}
