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
package ghidra.pcode.exec;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.*;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * Utilities for evaluating or executing Sleigh/p-code in the Debugger
 */
public enum DebuggerPcodeUtils {
	;

	/**
	 * Get a p-code executor state for the given coordinates
	 * 
	 * <p>
	 * If a thread is included, the executor state will have access to both the memory and registers
	 * in the context of that thread. Otherwise, only memory access is permitted.
	 * 
	 * @param tool the plugin tool
	 * @param coordinates the coordinates
	 * @return the state
	 */
	public static PcodeExecutorState<byte[]> executorStateForCoordinates(PluginTool tool,
			DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			throw new IllegalArgumentException("Coordinates have no trace");
		}
		TracePlatform platform = coordinates.getPlatform();
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException(
				"Given trace or platform does not use a Sleigh language");
		}
		DefaultPcodeDebuggerAccess access = new DefaultPcodeDebuggerAccess(tool,
			coordinates.getRecorder(), platform, coordinates.getViewSnap());
		PcodeExecutorState<byte[]> shared =
			new RWTargetMemoryPcodeExecutorState(access.getDataForSharedState(), Mode.RW);
		if (coordinates.getThread() == null) {
			return shared;
		}
		PcodeExecutorState<byte[]> local = new RWTargetRegistersPcodeExecutorState(
			access.getDataForLocalState(coordinates.getThread(), coordinates.getFrame()), Mode.RW);
		return new ThreadPcodeExecutorState<>(shared, local) {
			@Override
			public void clear() {
				shared.clear();
				local.clear();
			}
		};
	}

	/**
	 * Get an executor which can be used to evaluate Sleigh expressions at the given coordinates
	 * 
	 * <p>
	 * If a thread is included, the executor will have access to both the memory and registers in
	 * the context of that thread. Otherwise, only memory access is permitted.
	 * 
	 * @param tool the plugin tool. TODO: This shouldn't be required
	 * @param coordinates the coordinates
	 * @return the executor
	 */
	public static PcodeExecutor<byte[]> executorForCoordinates(PluginTool tool,
			DebuggerCoordinates coordinates) {
		PcodeExecutorState<byte[]> state = executorStateForCoordinates(tool, coordinates);

		SleighLanguage slang = (SleighLanguage) state.getLanguage();
		return new PcodeExecutor<>(slang, BytesPcodeArithmetic.forLanguage(slang), state,
			Reason.INSPECT);
	}

	/**
	 * The value of a watch expression including its state, address, and addresses read
	 */
	public record WatchValue(byte[] bytes, TraceMemoryState state, Address address,
			AddressSetView reads) {
	}

	/**
	 * A p-code arithmetic on watch values
	 * 
	 * <p>
	 * This is just a composition of four arithmetics. Using Pair<A,Pair<B,Pair<C,D>> would be
	 * unwieldy.
	 */
	public enum WatchValuePcodeArithmetic implements PcodeArithmetic<WatchValue> {
		BIG_ENDIAN(BytesPcodeArithmetic.BIG_ENDIAN),
		LITTLE_ENDIAN(BytesPcodeArithmetic.LITTLE_ENDIAN);

		public static WatchValuePcodeArithmetic forEndian(boolean isBigEndian) {
			return isBigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
		}

		public static WatchValuePcodeArithmetic forLanguage(Language language) {
			return forEndian(language.isBigEndian());
		}

		private static final TraceMemoryStatePcodeArithmetic STATE =
			TraceMemoryStatePcodeArithmetic.INSTANCE;
		private static final AddressOfPcodeArithmetic ADDRESS =
			AddressOfPcodeArithmetic.INSTANCE;
		private static final AddressesReadPcodeArithmetic READS =
			AddressesReadPcodeArithmetic.INSTANCE;

		private final BytesPcodeArithmetic bytes;

		private WatchValuePcodeArithmetic(BytesPcodeArithmetic bytes) {
			this.bytes = bytes;
		}

		@Override
		public Endian getEndian() {
			return bytes.getEndian();
		}

		@Override
		public WatchValue unaryOp(int opcode, int sizeout, int sizein1, WatchValue in1) {
			return new WatchValue(
				bytes.unaryOp(opcode, sizeout, sizein1, in1.bytes),
				STATE.unaryOp(opcode, sizeout, sizein1, in1.state),
				ADDRESS.unaryOp(opcode, sizeout, sizein1, in1.address),
				READS.unaryOp(opcode, sizeout, sizein1, in1.reads));
		}

		@Override
		public WatchValue binaryOp(int opcode, int sizeout, int sizein1, WatchValue in1,
				int sizein2, WatchValue in2) {
			return new WatchValue(
				bytes.binaryOp(opcode, sizeout, sizein1, in1.bytes, sizein2, in2.bytes),
				STATE.binaryOp(opcode, sizeout, sizein1, in1.state, sizein2, in2.state),
				ADDRESS.binaryOp(opcode, sizeout, sizein1, in1.address, sizein2, in2.address),
				READS.binaryOp(opcode, sizeout, sizein1, in1.reads, sizein2, in2.reads));
		}

		@Override
		public WatchValue modBeforeStore(int sizeout, int sizeinAddress, WatchValue inAddress,
				int sizeinValue, WatchValue inValue) {
			return new WatchValue(
				bytes.modBeforeStore(sizeout, sizeinAddress, inAddress.bytes,
					sizeinValue, inValue.bytes),
				STATE.modBeforeStore(sizeout, sizeinAddress, inAddress.state,
					sizeinValue, inValue.state),
				ADDRESS.modBeforeStore(sizeout, sizeinAddress, inAddress.address,
					sizeinValue, inValue.address),
				READS.modBeforeStore(sizeout, sizeinAddress, inAddress.reads,
					sizeinValue, inValue.reads));
		}

		@Override
		public WatchValue modAfterLoad(int sizeout, int sizeinAddress, WatchValue inAddress,
				int sizeinValue, WatchValue inValue) {
			return new WatchValue(
				bytes.modAfterLoad(sizeout, sizeinAddress, inAddress.bytes,
					sizeinValue, inValue.bytes),
				STATE.modAfterLoad(sizeout, sizeinAddress, inAddress.state,
					sizeinValue, inValue.state),
				ADDRESS.modAfterLoad(sizeout, sizeinAddress, inAddress.address,
					sizeinValue, inValue.address),
				READS.modAfterLoad(sizeout, sizeinAddress, inAddress.reads,
					sizeinValue, inValue.reads));
		}

		@Override
		public WatchValue fromConst(byte[] value) {
			return new WatchValue(
				bytes.fromConst(value),
				STATE.fromConst(value),
				ADDRESS.fromConst(value),
				READS.fromConst(value));
		}

		@Override
		public byte[] toConcrete(WatchValue value, Purpose purpose) {
			return bytes.toConcrete(value.bytes, purpose);
		}

		@Override
		public long sizeOf(WatchValue value) {
			return bytes.sizeOf(value.bytes);
		}
	}

	public static class WatchValuePcodeExecutorStatePiece
			implements PcodeExecutorStatePiece<byte[], WatchValue> {
		private final PcodeExecutorStatePiece<byte[], byte[]> bytesPiece;
		private final PcodeExecutorStatePiece<byte[], TraceMemoryState> statePiece;
		private final PcodeExecutorStatePiece<byte[], Address> addressPiece;
		private final PcodeExecutorStatePiece<byte[], AddressSetView> readsPiece;

		private final PcodeArithmetic<WatchValue> arithmetic;

		public WatchValuePcodeExecutorStatePiece(
				PcodeExecutorStatePiece<byte[], byte[]> bytesPiece,
				PcodeExecutorStatePiece<byte[], TraceMemoryState> statePiece,
				PcodeExecutorStatePiece<byte[], Address> addressPiece,
				PcodeExecutorStatePiece<byte[], AddressSetView> readsPiece) {
			this.bytesPiece = bytesPiece;
			this.statePiece = statePiece;
			this.addressPiece = addressPiece;
			this.readsPiece = readsPiece;
			this.arithmetic = WatchValuePcodeArithmetic.forLanguage(bytesPiece.getLanguage());
		}

		@Override
		public Language getLanguage() {
			return bytesPiece.getLanguage();
		}

		@Override
		public PcodeArithmetic<byte[]> getAddressArithmetic() {
			return bytesPiece.getAddressArithmetic();
		}

		@Override
		public PcodeArithmetic<WatchValue> getArithmetic() {
			return arithmetic;
		}

		@Override
		public void setVar(AddressSpace space, byte[] offset, int size, boolean quantize,
				WatchValue val) {
			bytesPiece.setVar(space, offset, size, quantize, val.bytes);
			statePiece.setVar(space, offset, size, quantize, val.state);
			addressPiece.setVar(space, offset, size, quantize, val.address);
			readsPiece.setVar(space, offset, size, quantize, val.reads);
		}

		@Override
		public WatchValue getVar(AddressSpace space, byte[] offset, int size, boolean quantize,
				Reason reason) {
			return new WatchValue(
				bytesPiece.getVar(space, offset, size, quantize, reason),
				statePiece.getVar(space, offset, size, quantize, reason),
				addressPiece.getVar(space, offset, size, quantize, reason),
				readsPiece.getVar(space, offset, size, quantize, reason));
		}

		@Override
		public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
			return bytesPiece.getConcreteBuffer(address, purpose);
		}

		@Override
		public void clear() {
			bytesPiece.clear();
			statePiece.clear();
			addressPiece.clear();
			readsPiece.clear();
		}
	}

	public static class WatchValuePcodeExecutorState implements PcodeExecutorState<WatchValue> {
		private WatchValuePcodeExecutorStatePiece piece;

		public WatchValuePcodeExecutorState(WatchValuePcodeExecutorStatePiece piece) {
			this.piece = piece;
		}

		@Override
		public Language getLanguage() {
			return piece.getLanguage();
		}

		@Override
		public PcodeArithmetic<WatchValue> getArithmetic() {
			return piece.arithmetic;
		}

		@Override
		public void setVar(AddressSpace space, WatchValue offset, int size, boolean quantize,
				WatchValue val) {
			piece.setVar(space, offset.bytes, size, quantize, val);
		}

		@Override
		public WatchValue getVar(AddressSpace space, WatchValue offset, int size, boolean quantize,
				Reason reason) {
			return piece.getVar(space, offset.bytes, size, quantize, reason);
		}

		@Override
		public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
			return piece.getConcreteBuffer(address, purpose);
		}

		@Override
		public void clear() {
			piece.clear();
		}
	}

	public static WatchValuePcodeExecutorState buildWatchState(PluginTool tool,
			DebuggerCoordinates coordinates) {
		PcodeTraceDataAccess data = new DefaultPcodeTraceAccess(coordinates.getPlatform(),
			coordinates.getViewSnap(), coordinates.getSnap())
					.getDataForThreadState(coordinates.getThread(), coordinates.getFrame());
		PcodeExecutorState<byte[]> bytesState = executorStateForCoordinates(tool, coordinates);
		return new WatchValuePcodeExecutorState(new WatchValuePcodeExecutorStatePiece(
			bytesState,
			new TraceMemoryStatePcodeExecutorStatePiece(data),
			new AddressOfPcodeExecutorStatePiece(data.getLanguage()),
			new AddressesReadTracePcodeExecutorStatePiece(data)));
	}

	/**
	 * Build an executor that can compute watch values
	 * 
	 * <p>
	 * This computes the concrete value, its state, its address, and the set of physical addresses
	 * involved in the computation. <b>CAUTION:</b> This executor's state will attempt to read live
	 * machine state, if applicable. Use the executor in a background thread to avoid locking the
	 * GUI.
	 * 
	 * @param tool this plugin tool
	 * @param coordinates the coordinates providing context for the evaluation
	 * @return an executor for evaluating the watch
	 */
	public static PcodeExecutor<WatchValue> buildWatchExecutor(PluginTool tool,
			DebuggerCoordinates coordinates) {
		TracePlatform platform = coordinates.getPlatform();
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage slang)) {
			throw new IllegalArgumentException("Watch expressions require a Sleigh language");
		}
		WatchValuePcodeExecutorState state = buildWatchState(tool, coordinates);
		return new PcodeExecutor<>(slang, state.getArithmetic(), state, Reason.INSPECT);
	}
}
