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
package ghidra.app.plugin.core.debug.gui.emulation;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

import ghidra.app.plugin.core.debug.service.emulation.Mode;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.guest.TracePlatform;

public record LocAndVal(byte[] value, ValueLocation loc) {
	public enum LocAndValPcodeArithmetic implements PcodeArithmetic<LocAndVal> {
		BIG_ENDIAN(BytesPcodeArithmetic.BIG_ENDIAN, LocationPcodeArithmetic.BIG_ENDIAN),
		LITTLE_ENDIAN(BytesPcodeArithmetic.LITTLE_ENDIAN, LocationPcodeArithmetic.BIG_ENDIAN);

		public static LocAndValPcodeArithmetic forEndian(boolean isBigEndian) {
			return isBigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
		}

		public static LocAndValPcodeArithmetic forLanguage(Language language) {
			return forEndian(language.isBigEndian());
		}

		private final BytesPcodeArithmetic bytes;
		private final LocationPcodeArithmetic location;

		private LocAndValPcodeArithmetic(BytesPcodeArithmetic bytes,
				LocationPcodeArithmetic location) {
			this.bytes = bytes;
			this.location = location;
		}

		@Override
		public Class<LocAndVal> getDomain() {
			return LocAndVal.class;
		}

		@Override
		public Endian getEndian() {
			return bytes.getEndian();
		}

		@Override
		public LocAndVal unaryOp(int opcode, int sizeout, int sizein1, LocAndVal in1) {
			return new LocAndVal(
				bytes.unaryOp(opcode, sizeout, sizein1, in1.value),
				location.unaryOp(opcode, sizeout, sizein1, in1.loc));
		}

		@Override
		public LocAndVal binaryOp(int opcode, int sizeout, int sizein1, LocAndVal in1, int sizein2,
				LocAndVal in2) {
			return new LocAndVal(
				bytes.binaryOp(opcode, sizeout, sizein1, in1.value, sizein2, in2.value),
				location.binaryOp(opcode, sizeout, sizein1, in1.loc, sizein2, in2.loc));
		}

		@Override
		public LocAndVal modBeforeStore(int sizeinOffset, AddressSpace space, LocAndVal inOffset,
				int sizeinValue, LocAndVal inValue) {
			return new LocAndVal(
				bytes.modBeforeStore(sizeinOffset, space, inOffset.value, sizeinValue,
					inValue.value),
				location.modBeforeStore(sizeinOffset, space, inOffset.loc, sizeinValue,
					inValue.loc));
		}

		@Override
		public LocAndVal modAfterLoad(int sizeinOffset, AddressSpace space, LocAndVal inOffset,
				int sizeinValue, LocAndVal inValue) {
			return new LocAndVal(
				bytes.modAfterLoad(sizeinOffset, space, inOffset.value, sizeinValue, inValue.value),
				location.modAfterLoad(sizeinOffset, space, inOffset.loc, sizeinValue, inValue.loc));
		}

		@Override
		public LocAndVal fromConst(byte[] value) {
			return new LocAndVal(
				bytes.fromConst(value),
				location.fromConst(value));
		}

		@Override
		public byte[] toConcrete(LocAndVal value, Purpose purpose) {
			return bytes.toConcrete(value.value, purpose);
		}

		@Override
		public long sizeOf(LocAndVal value) {
			return bytes.sizeOf(value.value);
		}
	}

	public static class LocAndValPcodeExecutorStatePiece
			implements PcodeExecutorStatePiece<byte[], LocAndVal> {
		private final PcodeExecutorStatePiece<byte[], byte[]> bytesPiece;
		private final PcodeExecutorStatePiece<byte[], ValueLocation> locationPiece;

		private final PcodeArithmetic<LocAndVal> arithmetic;

		public LocAndValPcodeExecutorStatePiece(
				PcodeExecutorStatePiece<byte[], byte[]> bytesPiece,
				PcodeExecutorStatePiece<byte[], ValueLocation> locationPiece) {
			this.bytesPiece = bytesPiece;
			this.locationPiece = locationPiece;
			this.arithmetic = LocAndValPcodeArithmetic.forLanguage(bytesPiece.getLanguage());
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
		public PcodeArithmetic<LocAndVal> getArithmetic() {
			return arithmetic;
		}

		@Override
		public Stream<PcodeExecutorStatePiece<?, ?>> streamPieces() {
			return Stream.of(bytesPiece, locationPiece);
		}

		@Override
		public LocAndValPcodeExecutorStatePiece fork(PcodeStateCallbacks cb) {
			return new LocAndValPcodeExecutorStatePiece(
				bytesPiece.fork(cb),
				locationPiece.fork(cb));
		}

		@Override
		public void setVarInternal(AddressSpace space, byte[] offset, int size, LocAndVal val) {
			bytesPiece.setVarInternal(space, offset, size, val.value);
			locationPiece.setVarInternal(space, offset, size, val.loc);
		}

		@Override
		public void setVar(AddressSpace space, byte[] offset, int size, boolean quantize,
				LocAndVal val) {
			bytesPiece.setVar(space, offset, size, quantize, val.value);
			locationPiece.setVar(space, offset, size, quantize, val.loc);
		}

		@Override
		public LocAndVal getVar(AddressSpace space, byte[] offset, int size, boolean quantize,
				Reason reason) {
			return new LocAndVal(
				bytesPiece.getVar(space, offset, size, quantize, reason),
				locationPiece.getVar(space, offset, size, quantize, reason));
		}

		@Override
		public LocAndVal getVarInternal(AddressSpace space, byte[] offset, int size,
				Reason reason) {
			return new LocAndVal(
				bytesPiece.getVarInternal(space, offset, size, reason),
				locationPiece.getVarInternal(space, offset, size, reason));
		}

		@Override
		public Map<Register, LocAndVal> getRegisterValues() {
			Map<Register, LocAndVal> result = new HashMap<>();
			for (Entry<Register, byte[]> entry : bytesPiece.getRegisterValues().entrySet()) {
				Register reg = entry.getKey();
				AddressSpace space = reg.getAddressSpace();
				long offset = reg.getAddress().getOffset();
				int size = reg.getNumBytes();
				result.put(reg, new LocAndVal(
					entry.getValue(),
					locationPiece.getVar(space, offset, size, false, Reason.INSPECT)));
			}
			return result;
		}

		@Override
		public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
			return bytesPiece.getConcreteBuffer(address, purpose);
		}

		@Override
		public void clear() {
			bytesPiece.clear();
			locationPiece.clear();
		}
	}

	public static class LocAndValPcodeExecutorState
			extends AbstractPcodeExecutorState<byte[], LocAndVal> {

		public LocAndValPcodeExecutorState(PcodeExecutorStatePiece<byte[], LocAndVal> piece) {
			super(piece);
		}

		@Override
		protected byte[] extractAddress(LocAndVal value) {
			return value.value;
		}

		@Override
		public LocAndValPcodeExecutorState fork(PcodeStateCallbacks cb) {
			return new LocAndValPcodeExecutorState(piece.fork(cb));
		}
	}

	public record WriterAndState(Writer writer, LocAndValPcodeExecutorState state) {}

	public static WriterAndState buildState(ServiceProvider provider,
			DebuggerCoordinates coordinates) {
		PcodeTraceDataAccess data = new DefaultPcodeTraceAccess(coordinates.getPlatform(),
			coordinates.getViewSnap(), coordinates.getSnap())
					.getDataForThreadState(coordinates.getThread(), coordinates.getFrame());
		// Seems weird, but RO is in terms of the Target. RO writes the Trace.
		DebuggerPcodeUtils.WriterAndState ws =
			DebuggerPcodeUtils.executorStateForCoordinates(provider, coordinates, Mode.RO);
		return new WriterAndState(ws.writer(),
			new LocAndValPcodeExecutorState(new LocAndValPcodeExecutorStatePiece(ws.state(),
				new LocationPcodeExecutorStatePiece(data.getLanguage()))));
	}

	public record WriterAndExecutor(Writer writer, PcodeExecutor<LocAndVal> executor) {}

	public static WriterAndExecutor buildExecutor(ServiceProvider provider,
			DebuggerCoordinates coordinates) {
		TracePlatform platform = coordinates.getPlatform();
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage slang)) {
			throw new IllegalArgumentException("Emulation requires a Sleigh language");
		}
		WriterAndState ws = buildState(provider, coordinates);
		return new WriterAndExecutor(ws.writer,
			new PcodeExecutor<>(slang, ws.state.getArithmetic(), ws.state, Reason.INSPECT));
	}
}
