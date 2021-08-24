package ghidra.pcode.emu;

import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

public class ThreadPcodeExecutorState<T> implements PcodeExecutorState<T> {
	protected final PcodeExecutorState<T> sharedState;
	protected final PcodeExecutorState<T> localState;

	public ThreadPcodeExecutorState(PcodeExecutorState<T> sharedState,
			PcodeExecutorState<T> localState) {
		this.sharedState = sharedState;
		this.localState = localState;
	}

	protected boolean isThreadLocalSpace(AddressSpace space) {
		return space.isRegisterSpace() || space.isUniqueSpace();
	}

	@Override
	public T longToOffset(AddressSpace space, long l) {
		if (isThreadLocalSpace(space)) {
			return localState.longToOffset(space, l);
		}
		else {
			return sharedState.longToOffset(space, l);
		}
	}

	@Override
	public void setVar(AddressSpace space, T offset, int size, boolean truncateAddressableUnit,
			T val) {
		if (isThreadLocalSpace(space)) {
			localState.setVar(space, offset, size, truncateAddressableUnit, val);
		}
		else {
			sharedState.setVar(space, offset, size, truncateAddressableUnit, val);
		}
	}

	@Override
	public T getVar(AddressSpace space, T offset, int size, boolean truncateAddressableUnit) {
		if (isThreadLocalSpace(space)) {
			return localState.getVar(space, offset, size, truncateAddressableUnit);
		}
		else {
			return sharedState.getVar(space, offset, size, truncateAddressableUnit);
		}
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		assert !isThreadLocalSpace(address.getAddressSpace());
		return sharedState.getConcreteBuffer(address);
	}

	public PcodeExecutorState<T> getSharedState() {
		return sharedState;
	}

	public PcodeExecutorState<T> getLocalState() {
		return localState;
	}
}