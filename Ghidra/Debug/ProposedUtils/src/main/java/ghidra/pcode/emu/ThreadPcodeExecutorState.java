package ghidra.pcode.emu;

import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

public class ThreadPcodeExecutorState<T> implements PcodeExecutorState<T> {
	protected final PcodeExecutorState<T> memoryState;
	protected final PcodeExecutorState<T> registerState;

	public ThreadPcodeExecutorState(PcodeExecutorState<T> memoryState,
			PcodeExecutorState<T> registerState) {
		this.memoryState = memoryState;
		this.registerState = registerState;
	}

	@Override
	public T longToOffset(AddressSpace space, long l) {
		if (space.isRegisterSpace()) {
			return registerState.longToOffset(space, l);
		}
		else {
			return memoryState.longToOffset(space, l);
		}
	}

	@Override
	public void setVar(AddressSpace space, T offset, int size, boolean truncateAddressableUnit,
			T val) {
		if (space.isRegisterSpace()) {
			registerState.setVar(space, offset, size, truncateAddressableUnit, val);
		}
		else {
			memoryState.setVar(space, offset, size, truncateAddressableUnit, val);
		}
	}

	@Override
	public T getVar(AddressSpace space, T offset, int size, boolean truncateAddressableUnit) {
		if (space.isRegisterSpace()) {
			return registerState.getVar(space, offset, size, truncateAddressableUnit);
		}
		else {
			return memoryState.getVar(space, offset, size, truncateAddressableUnit);
		}
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		assert !address.getAddressSpace().isRegisterSpace();
		return memoryState.getConcreteBuffer(address);
	}

	public PcodeExecutorState<T> getMemoryState() {
		return memoryState;
	}

	public PcodeExecutorState<T> getRegisterState() {
		return registerState;
	}
}