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
package ghidra.app.plugin.core.debug.service.emulation;

import java.util.concurrent.*;

import ghidra.debug.api.emulation.*;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TraceEmulationIntegration;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.*;
import ghidra.pcode.exec.trace.data.*;
import ghidra.program.model.address.*;
import ghidra.trace.model.thread.TraceThread;

/**
 * A collection of static methods for integrating an emulator with a trace and target.
 */
public enum DebuggerEmulationIntegration {
	;

	private static <T> Writer createDelayedWrite(PcodeDebuggerAccess acc, Mode mode) {
		Writer writer = new TraceWriter(acc);
		writer.putHandler(new TargetBytesPieceHandler(mode));
		return writer;
	}

	/**
	 * Create a writer (callbacks) that lazily loads data from the given access shim.
	 * 
	 * <p>
	 * Reads may be redirected to the target. Writes are logged, but <em>never</em> sent to the
	 * target. This is used for forking emulation from a chosen snapshot and saving the results into
	 * (usually scratch) snapshots. This is the pattern used by the UI when emulation schedules are
	 * requested.
	 * 
	 * @see TraceEmulationIntegration#bytesDelayedWrite(PcodeTraceAccess)
	 * @param from the access shim for lazy loads
	 * @return the writer
	 */
	public static Writer bytesDelayedWriteTrace(PcodeDebuggerAccess from) {
		return createDelayedWrite(from, Mode.RO);
	}

	/**
	 * Create a writer (callbacks) that lazily loads data and immediately writes changes to the
	 * given access shim.
	 * 
	 * <p>
	 * Reads may be redirected to the target. If redirected, writes are immediately sent to the
	 * target and presumably stored into the trace at the same snapshot as state is sourced.
	 * 
	 * @see TraceEmulationIntegration#bytesImmediateWrite(PcodeTraceAccess)
	 * @param access the access shim for loads and stores
	 * @return the writer
	 */
	public static Writer bytesImmediateWriteTarget(PcodeDebuggerAccess access) {
		return createDelayedWrite(access, Mode.RW);
	}

	/**
	 * Create state callbacks that lazily load data and immediately write changes to the given
	 * access shim.
	 * 
	 * <p>
	 * Reads may be redirected to the target. If redirected, writes are immediately sent to the
	 * target and presumably stored into the trace at the same snapshot as state is sourced.
	 *
	 * <p>
	 * Use this instead of {@link #bytesImmediateWriteTarget(PcodeDebuggerAccess)} when interfacing
	 * directly with a {@link PcodeExecutorState} vice a {@link PcodeEmulator}.
	 * 
	 * @see TraceEmulationIntegration#bytesImmediateWrite(PcodeTraceAccess, TraceThread, int)
	 * @param access the access shim for loads and stores
	 * @param thread the trace thread for register accesses
	 * @param frame the frame for register accesses, usually 0
	 * @return the callbacks
	 */
	public static PcodeStateCallbacks bytesImmediateWriteTarget(PcodeDebuggerAccess access,
			TraceThread thread, int frame) {
		PcodeDebuggerRegistersAccess regAcc = access.getDataForLocalState(thread, frame);
		Writer writer = new TraceWriter(access) {
			@Override
			protected PcodeTraceRegistersAccess getRegAccess(PcodeThread<?> ignored) {
				return regAcc;
			}
		};
		writer.putHandler(new TargetBytesPieceHandler(Mode.RW));
		return writer.wrapFor(null);
	}

	protected static <T> T waitTimeout(CompletableFuture<T> future) {
		try {
			return future.get(1, TimeUnit.SECONDS);
		}
		catch (TimeoutException e) {
			throw new AccessPcodeExecutionException("Timed out reading or writing target", e);
		}
		catch (InterruptedException | ExecutionException e) {
			throw new AccessPcodeExecutionException("Error reading or writing target", e);
		}
	}

	/**
	 * An extension/replacement of the {@link BytesPieceHandler} that may redirect reads and writes
	 * to/from the target.
	 * 
	 * @implNote Because piece handlers are keyed by (address-domain, value-domain), adding this to
	 *           a writer will replace the default handler.
	 */
	public static class TargetBytesPieceHandler extends BytesPieceHandler {
		protected final Mode mode;

		public TargetBytesPieceHandler(Mode mode) {
			this.mode = mode;
		}

		@Override
		public AddressSetView readUninitialized(PcodeTraceDataAccess acc, PcodeThread<?> thread,
				PcodeExecutorStatePiece<byte[], byte[]> piece, AddressSetView set) {
			AddressSetView unknown = acc.intersectUnknown(set);
			if (unknown.isEmpty()) {
				return super.readUninitialized(acc, thread, piece, set);
			}
			if (acc instanceof PcodeDebuggerRegistersAccess regsAcc) {
				if (regsAcc.isLive()) {
					waitTimeout(regsAcc.readFromTargetRegisters(unknown));
				}
				/**
				 * Pass `set` to super, because even if regsAcc has just read from target into
				 * trace, we have yet to read from trace into state piece.
				 */
				return super.readUninitialized(acc, thread, piece, set);
			}
			if (acc instanceof PcodeDebuggerMemoryAccess memAcc) {
				if (memAcc.isLive() && waitTimeout(memAcc.readFromTargetMemory(unknown))) {
					unknown = memAcc.intersectUnknown(set);
					if (unknown.isEmpty()) {
						return super.readUninitialized(acc, thread, piece, set);
					}
				}
				AddressSetView remains = memAcc.readFromStaticImages(piece, unknown);
				/**
				 * In this case, readFromStaticImages has in fact modified the state piece, so we to
				 * compute what that was and remove it from the original request. The rest still
				 * needs to be read from the trace into the piece, which is done by the super call.
				 */
				AddressSetView readFromStatic = unknown.subtract(remains);
				AddressSetView toReadFromTraceToPiece = set.subtract(readFromStatic);
				return super.readUninitialized(memAcc, thread, piece, toReadFromTraceToPiece);
			}
			throw new AssertionError();
		}

		@Override
		public boolean dataWritten(PcodeTraceDataAccess acc, AddressSet written,
				PcodeThread<?> thread, PcodeExecutorStatePiece<byte[], byte[]> piece,
				Address address, int length, byte[] value) {
			if (!mode.isWriteTarget()) {
				return false; // Log it as written, so it goes to the trace
			}
			if (address.isUniqueAddress()) {
				return true;
			}
			if (acc instanceof PcodeDebuggerRegistersAccess regsAcc) {
				if (!regsAcc.isLive()) {
					return true;
				}
				waitTimeout(regsAcc.writeTargetRegister(address, value));
				// Change should get recorded by back-end, if successful
			}
			else if (acc instanceof PcodeDebuggerMemoryAccess memAcc) {
				if (!memAcc.isLive()) {
					return true;
				}
				waitTimeout(memAcc.writeTargetMemory(address, value));
				// Change should get recorded by back-end, if successful
			}
			return true;
		}
	}
}
