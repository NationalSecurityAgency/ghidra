/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcode.emu;

import java.util.List;

import ghidra.pcode.exec.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A mechanism for broadcasting (mostly) callbacks among several receivers.
 * 
 * <p>
 * The two (currently) methods that do not implement a pure broadcast pattern are
 * {@link #handleMissingUserop(PcodeThread, PcodeOp, PcodeFrame, String, PcodeUseropLibrary)} and
 * {@link #readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSetView)}. For a missing
 * userop, it will terminate after the first delegate returns {@code true}, in which case it also
 * returns {@code true}. If all delegates return {@code false}, then it returns {@code false}. For
 * an uninitialized read, each delegate's returned "still-uninitialized" set is passed to the
 * subsequent delegate. The first delegate gets the set as passed into the composition. The set
 * returned by the composition is that returned by the last delegate. This terminates early when any
 * delegate returns the empty set.
 * 
 * <p>
 * One (currently) other method has a non-void return type:
 * {@link #readUninitialized(PcodeThread, PcodeExecutorStatePiece, AddressSpace, Object, int)}. The
 * callback is broadcast as expected, and the return value is the max returned by the delegates.
 * 
 * @param <T> the emulator's value domain
 */
public class ComposedPcodeEmulationCallbacks<T> implements PcodeEmulationCallbacks<T> {
	private final List<PcodeEmulationCallbacks<T>> delegates;

	/**
	 * Construct a composition of delegate callbacks
	 * 
	 * @param delegates the delegates
	 */
	@SafeVarargs
	public ComposedPcodeEmulationCallbacks(PcodeEmulationCallbacks<T>... delegates) {
		this.delegates = List.of(delegates);
	}

	@Override
	public void emulatorCreated(PcodeMachine<T> machine) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.emulatorCreated(machine);
		}
	}

	@Override
	public void sharedStateCreated(PcodeMachine<T> machine) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.sharedStateCreated(machine);
		}
	}

	@Override
	public void threadCreated(PcodeThread<T> thread) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.threadCreated(thread);
		}
	}

	@Override
	public PcodeProgram getInject(PcodeThread<T> thread, Address address) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			PcodeProgram inject = d.getInject(thread, address);
			if (inject != null) {
				return inject;
			}
		}
		return null;
	}

	@Override
	public void beforeExecuteInject(PcodeThread<T> thread, Address address, PcodeProgram program) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.beforeExecuteInject(thread, address, program);
		}
	}

	@Override
	public void afterExecuteInject(PcodeThread<T> thread, Address address) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.afterExecuteInject(thread, address);
		}
	}

	@Override
	public void beforeDecodeInstruction(PcodeThread<T> thread, Address counter,
			RegisterValue context) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.beforeDecodeInstruction(thread, counter, context);
		}
	}

	@Override
	public void beforeExecuteInstruction(PcodeThread<T> thread, Instruction instruction,
			PcodeProgram program) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.beforeExecuteInstruction(thread, instruction, program);
		}
	}

	@Override
	public void afterExecuteInstruction(PcodeThread<T> thread, Instruction instruction) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.afterExecuteInstruction(thread, instruction);
		}
	}

	@Override
	public void beforeStepOp(PcodeThread<T> thread, PcodeOp op, PcodeFrame frame) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.beforeStepOp(thread, op, frame);
		}
	}

	@Override
	public void afterStepOp(PcodeThread<T> thread, PcodeOp op, PcodeFrame frame) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.afterStepOp(thread, op, frame);
		}
	}

	@Override
	public void beforeLoad(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.beforeLoad(thread, op, space, offset, size);
		}
	}

	@Override
	public void afterLoad(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset, int size,
			T value) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.afterLoad(thread, op, space, offset, size, value);
		}
	}

	@Override
	public void beforeStore(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size, T value) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.beforeStore(thread, op, space, offset, size, value);
		}
	}

	@Override
	public void afterStore(PcodeThread<T> thread, PcodeOp op, AddressSpace space, T offset,
			int size, T value) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.afterStore(thread, op, space, offset, size, value);
		}
	}

	@Override
	public void afterBranch(PcodeThread<T> thread, PcodeOp op, Address target) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.afterBranch(thread, op, target);
		}
	}

	@Override
	public boolean handleMissingUserop(PcodeThread<T> thread, PcodeOp op, PcodeFrame frame,
			String opName, PcodeUseropLibrary<T> library) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			if (d.handleMissingUserop(thread, op, frame, opName, library)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public <A, U> void dataWritten(PcodeThread<T> thread, PcodeExecutorStatePiece<A, U> piece,
			AddressSpace space, A offset, int length, U value) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.dataWritten(thread, piece, space, offset, length, value);
		}
	}

	@Override
	public <A, U> void dataWritten(PcodeThread<T> thread, PcodeExecutorStatePiece<A, U> piece,
			Address address, int length, U value) {
		for (PcodeEmulationCallbacks<T> d : delegates) {
			d.dataWritten(thread, piece, address, length, value);
		}
	}

	@Override
	public <A, U> int readUninitialized(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSpace space, A offset, int length) {
		/**
		 * NOTE: This could use some work. It's a bit onerous to specify arbitrary, possibly
		 * disjoint, sets of offsets of type A. Can only be guaranteed to mean something if A is
		 * comparable, and I don't want to start imposing that requirements formally. What I have
		 * here is already complicated enough, if it even gets used. I'll wait for the need to arise
		 * to make this any more sophisticated.
		 */
		int maxL = 0;
		for (PcodeEmulationCallbacks<T> d : delegates) {
			maxL = Math.max(maxL, d.readUninitialized(thread, piece, space, offset, length));
			if (maxL == length) {
				return maxL;
			}
		}
		return maxL;
	}

	@Override
	public <A, U> AddressSetView readUninitialized(PcodeThread<T> thread,
			PcodeExecutorStatePiece<A, U> piece, AddressSetView set) {
		AddressSetView remains = set;
		for (PcodeEmulationCallbacks<T> d : delegates) {
			remains = d.readUninitialized(thread, piece, remains);
			if (remains.isEmpty()) {
				return remains;
			}
		}
		return remains;
	}
}
