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

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.SleighProgramCompiler.ErrorCollectingPcodeParser;
import ghidra.pcode.exec.trace.*;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.pcode.utils.Utils;
import ghidra.pcodeCPort.slghsymbol.SleighSymbol;
import ghidra.pcodeCPort.slghsymbol.VarnodeSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramLocation;
import ghidra.sleigh.grammar.Location;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.symbol.TraceSymbol;
import ghidra.trace.model.symbol.TraceSymbolWithLifespan;
import ghidra.util.NumericUtilities;

/**
 * Utilities for evaluating or executing Sleigh/p-code in the Debugger
 */
public enum DebuggerPcodeUtils {
	;

	/**
	 * A p-code parser that can resolve labels from a trace or its mapped programs.
	 */
	public static class LabelBoundPcodeParser extends ErrorCollectingPcodeParser {
		record ProgSym(String sourceName, String nm, Address address) {
		}

		private final DebuggerStaticMappingService mappings;
		private final DebuggerCoordinates coordinates;

		/**
		 * Construct a parser bound to the given coordinates
		 * 
		 * @param tool the tool for the mapping service
		 * @param coordinates the current coordinates for context
		 */
		public LabelBoundPcodeParser(PluginTool tool, DebuggerCoordinates coordinates) {
			super((SleighLanguage) coordinates.getPlatform().getLanguage());
			this.mappings = tool.getService(DebuggerStaticMappingService.class);
			this.coordinates = coordinates;
		}

		protected SleighSymbol createSleighConstant(String sourceName, String nm, Address address) {
			return new VarnodeSymbol(new Location(sourceName, 0), nm, getConstantSpace(),
				address.getOffset(), address.getAddressSpace().getPointerSize());
		}

		@Override
		public SleighSymbol findSymbol(String nm) {
			SleighSymbol symbol = null;
			try {
				symbol = super.findSymbol(nm);
			}
			catch (SleighException e) {
				// leave null
			}
			if (symbol == null) {
				symbol = findUserSymbol(nm);
			}
			if (symbol == null) {
				/**
				 * TODO: This may break things that check for the absence of a symbol
				 * 
				 * I don't think it'll affect expressions, but it could later affect user Sleigh
				 * libraries than an expression might like to use. The better approach would be
				 * to incorporate a better error message into the Sleigh compiler, but it won't
				 * always know the use case for a clear message.
				 */
				throw new SleighException("Unknown register or label: '" + nm + "'");
			}
			return symbol;
		}

		protected SleighSymbol findUserSymbol(String nm) {
			Trace trace = coordinates.getTrace();
			long snap = coordinates.getSnap();
			for (TraceSymbol symbol : trace.getSymbolManager()
					.labelsAndFunctions()
					.getNamed(nm)) {
				if (symbol instanceof TraceSymbolWithLifespan lifeSym &&
					!lifeSym.getLifespan().contains(snap)) {
					continue;
				}
				return createSleighConstant(trace.getName(), nm, symbol.getAddress());
			}
			for (Program program : mappings.getOpenMappedProgramsAtSnap(trace, snap)) {
				for (Symbol symbol : program.getSymbolTable().getSymbols(nm)) {
					if (symbol.isDynamic() || symbol.isExternal()) {
						continue;
					}
					if (symbol.getSymbolType() != SymbolType.FUNCTION &&
						symbol.getSymbolType() != SymbolType.LABEL) {
						continue;
					}
					TraceLocation tloc = mappings.getOpenMappedLocation(trace,
						new ProgramLocation(program, symbol.getAddress()), snap);
					if (tloc == null) {
						return null;
					}
					return createSleighConstant(program.getName(), nm, tloc.getAddress());
				}
			}
			return null;
		}
	}

	/**
	 * Compile the given Sleigh source into a p-code program, resolving user labels
	 *
	 * <p>
	 * The resulting program must only be used with a state bound to the same coordinates. Any
	 * symbols which are resolved to labels in the trace or its mapped programs are effectively
	 * substituted for their offsets. If a label moves, the program should be recompiled in order to
	 * update those substitutions.
	 * 
	 * @param tool the tool for context
	 * @param coordinates the coordinates for the trace (and programs) from which labels can be
	 *            resolved
	 * @see SleighProgramCompiler#compileProgram(PcodeParser, SleighLanguage, String, String,
	 *      PcodeUseropLibrary)
	 */
	public static PcodeProgram compileProgram(PluginTool tool, DebuggerCoordinates coordinates,
			String sourceName, String source, PcodeUseropLibrary<?> library) {
		return SleighProgramCompiler.compileProgram(new LabelBoundPcodeParser(tool, coordinates),
			(SleighLanguage) coordinates.getPlatform().getLanguage(), sourceName, source, library);
	}

	/**
	 * Compile the given Sleigh expression into a p-code program, resolving user labels
	 *
	 * <p>
	 * This has the same limitations as
	 * {@link #compileProgram(PluginTool, DebuggerCoordinates, String, String, PcodeUseropLibrary)}
	 * 
	 * @see SleighProgramCompiler#compileExpression(PcodeParser, SleighLanguage, String)
	 */
	public static PcodeExpression compileExpression(PluginTool tool,
			DebuggerCoordinates coordinates, String source) {
		return SleighProgramCompiler.compileExpression(new LabelBoundPcodeParser(tool, coordinates),
			(SleighLanguage) coordinates.getPlatform().getLanguage(), source);
	}

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
			access.getDataForLocalState(coordinates.getThread(), coordinates.getFrame()),
			Mode.RW);
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
	 * A wrapper on a byte array to pretty print it
	 */
	public record PrettyBytes(boolean bigEndian, byte[] bytes) {
		@Override
		public byte[] bytes() {
			return Arrays.copyOf(bytes, bytes.length);
		}

		@Override
		public String toString() {
			return "PrettyBytes[bigEndian=" + bigEndian + ",bytes=" +
				NumericUtilities.convertBytesToString(bytes, ":") + ",value=" +
				toBigInteger(false) + "]";
		}

		/**
		 * Render at most 256 bytes in lines of 16 space-separated bytes each
		 * 
		 * <p>
		 * If the total exceeds 256 bytes, the last line will contain ellipses and indicate the
		 * total size in bytes.
		 * 
		 * @return the rendered string
		 */
		public String toBytesString() {
			StringBuffer buf = new StringBuffer();
			boolean first = true;
			for (int i = 0; i < bytes.length; i += 16) {
				if (i >= 256) {
					buf.append("\n... (count=");
					buf.append(bytes.length);
					buf.append(")");
					break;
				}
				if (first) {
					first = false;
				}
				else {
					buf.append('\n');
				}
				int len = Math.min(16, bytes.length - i);
				buf.append(NumericUtilities.convertBytesToString(bytes, i, len, " "));
			}
			return buf.toString();
		}

		/**
		 * Render the bytes as an unsigned decimal integer
		 * 
		 * <p>
		 * The endianness is taken from {@link #bigEndian()}
		 * 
		 * @return the rendered string
		 */
		public String toIntegerString() {
			return toBigInteger(false).toString();
		}

		/**
		 * Collect various integer representations: signed, unsigned; decimal, hexadecimal
		 * 
		 * <p>
		 * This only presents those forms that differ from those already offered. The preferred form
		 * is unsigned decimal. If all four differ, then they are formatted on two lines: unsigned
		 * then signed.
		 * 
		 * @return the rendered string
		 */
		public String collectDisplays() {
			BigInteger unsigned = toBigInteger(false);
			StringBuffer sb = new StringBuffer();
			String uDec = unsigned.toString();
			sb.append(uDec);
			String uHex = unsigned.toString(16);
			boolean radixMatters = !uHex.equals(uDec);
			if (radixMatters) {
				sb.append(", 0x");
				sb.append(uHex);
			}
			BigInteger signed = toBigInteger(true);
			if (!signed.equals(unsigned)) {
				sb.append(radixMatters ? "\n" : ", ");
				String sDec = signed.toString();
				sb.append(sDec);
				String sHex = signed.toString(16);
				if (!sHex.equals(sDec)) {
					sb.append(", -0x");
					sb.append(sHex.subSequence(1, sHex.length()));
				}
			}
			return sb.toString();
		}

		@Override
		public boolean equals(Object o) {
			if (o == this) {
				return true;
			}
			if (!(o instanceof PrettyBytes that)) {
				return false;
			}
			if (this.bigEndian != that.bigEndian) {
				return false;
			}
			return Arrays.equals(this.bytes, that.bytes);
		}

		/**
		 * Convert the array to a big integer with the given signedness
		 * 
		 * @param signed true for signed, false for unsigned
		 * @return the big integer
		 */
		public BigInteger toBigInteger(boolean signed) {
			return Utils.bytesToBigInteger(bytes, bytes.length, bigEndian, signed);
		}

		/**
		 * Get the number of bytes
		 * 
		 * @return the count
		 */
		public int length() {
			return bytes.length;
		}
	}

	/**
	 * The value of a watch expression including its state, location, and addresses read
	 */
	public record WatchValue(PrettyBytes bytes, TraceMemoryState state, ValueLocation location,
			AddressSetView reads) {
		/**
		 * Get the value as a big integer with the given signedness
		 * 
		 * @param signed true for signed, false for unsigned
		 * @return the big integer
		 */
		public BigInteger toBigInteger(boolean signed) {
			return bytes.toBigInteger(signed);
		}

		public Address address() {
			return location == null ? null : location.getAddress();
		}

		/**
		 * Get the number of bytes
		 * 
		 * @return the count
		 */
		public int length() {
			return bytes.length();
		}
	}

	/**
	 * A p-code arithmetic on watch values
	 * 
	 * <p>
	 * This is just a composition of four arithmetics. Using Pair<A,Pair<B,Pair<C,D>> would be
	 * unwieldy.
	 */
	public enum WatchValuePcodeArithmetic implements PcodeArithmetic<WatchValue> {
		BIG_ENDIAN(BytesPcodeArithmetic.BIG_ENDIAN, LocationPcodeArithmetic.BIG_ENDIAN),
		LITTLE_ENDIAN(BytesPcodeArithmetic.LITTLE_ENDIAN, LocationPcodeArithmetic.LITTLE_ENDIAN);

		public static WatchValuePcodeArithmetic forEndian(boolean isBigEndian) {
			return isBigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
		}

		public static WatchValuePcodeArithmetic forLanguage(Language language) {
			return forEndian(language.isBigEndian());
		}

		private static final TraceMemoryStatePcodeArithmetic STATE =
			TraceMemoryStatePcodeArithmetic.INSTANCE;
		private static final AddressesReadPcodeArithmetic READS =
			AddressesReadPcodeArithmetic.INSTANCE;

		private final BytesPcodeArithmetic bytes;
		private final LocationPcodeArithmetic location;

		private WatchValuePcodeArithmetic(BytesPcodeArithmetic bytes,
				LocationPcodeArithmetic location) {
			this.bytes = bytes;
			this.location = location;
		}

		@Override
		public Endian getEndian() {
			return bytes.getEndian();
		}

		@Override
		public WatchValue unaryOp(int opcode, int sizeout, int sizein1, WatchValue in1) {
			return new WatchValue(
				new PrettyBytes(getEndian().isBigEndian(),
					bytes.unaryOp(opcode, sizeout, sizein1, in1.bytes.bytes)),
				STATE.unaryOp(opcode, sizeout, sizein1, in1.state),
				location.unaryOp(opcode, sizeout, sizein1, in1.location),
				READS.unaryOp(opcode, sizeout, sizein1, in1.reads));
		}

		@Override
		public WatchValue binaryOp(int opcode, int sizeout, int sizein1, WatchValue in1,
				int sizein2, WatchValue in2) {
			return new WatchValue(
				new PrettyBytes(getEndian().isBigEndian(),
					bytes.binaryOp(opcode, sizeout, sizein1, in1.bytes.bytes, sizein2,
						in2.bytes.bytes)),
				STATE.binaryOp(opcode, sizeout, sizein1, in1.state, sizein2, in2.state),
				location.binaryOp(opcode, sizeout, sizein1, in1.location, sizein2,
					in2.location),
				READS.binaryOp(opcode, sizeout, sizein1, in1.reads, sizein2, in2.reads));
		}

		@Override
		public WatchValue modBeforeStore(int sizeout, int sizeinAddress, WatchValue inAddress,
				int sizeinValue, WatchValue inValue) {
			return new WatchValue(
				new PrettyBytes(inValue.bytes.bigEndian,
					bytes.modBeforeStore(sizeout, sizeinAddress, inAddress.bytes.bytes,
						sizeinValue, inValue.bytes.bytes)),
				STATE.modBeforeStore(sizeout, sizeinAddress, inAddress.state,
					sizeinValue, inValue.state),
				location.modBeforeStore(sizeout, sizeinAddress, inAddress.location,
					sizeinValue, inValue.location),
				READS.modBeforeStore(sizeout, sizeinAddress, inAddress.reads,
					sizeinValue, inValue.reads));
		}

		@Override
		public WatchValue modAfterLoad(int sizeout, int sizeinAddress, WatchValue inAddress,
				int sizeinValue, WatchValue inValue) {
			return new WatchValue(
				new PrettyBytes(getEndian().isBigEndian(),
					bytes.modAfterLoad(sizeout, sizeinAddress, inAddress.bytes.bytes,
						sizeinValue, inValue.bytes.bytes)),
				STATE.modAfterLoad(sizeout, sizeinAddress, inAddress.state,
					sizeinValue, inValue.state),
				location.modAfterLoad(sizeout, sizeinAddress, inAddress.location,
					sizeinValue, inValue.location),
				READS.modAfterLoad(sizeout, sizeinAddress, inAddress.reads,
					sizeinValue, inValue.reads));
		}

		@Override
		public WatchValue fromConst(byte[] value) {
			return new WatchValue(
				new PrettyBytes(getEndian().isBigEndian(), bytes.fromConst(value)),
				STATE.fromConst(value),
				location.fromConst(value),
				READS.fromConst(value));
		}

		@Override
		public byte[] toConcrete(WatchValue value, Purpose purpose) {
			return bytes.toConcrete(value.bytes.bytes, purpose);
		}

		@Override
		public long sizeOf(WatchValue value) {
			return bytes.sizeOf(value.bytes.bytes);
		}
	}

	public static class WatchValuePcodeExecutorStatePiece
			implements PcodeExecutorStatePiece<byte[], WatchValue> {
		private final PcodeExecutorStatePiece<byte[], byte[]> bytesPiece;
		private final PcodeExecutorStatePiece<byte[], TraceMemoryState> statePiece;
		private final PcodeExecutorStatePiece<byte[], ValueLocation> locationPiece;
		private final PcodeExecutorStatePiece<byte[], AddressSetView> readsPiece;

		private final PcodeArithmetic<WatchValue> arithmetic;

		public WatchValuePcodeExecutorStatePiece(
				PcodeExecutorStatePiece<byte[], byte[]> bytesPiece,
				PcodeExecutorStatePiece<byte[], TraceMemoryState> statePiece,
				PcodeExecutorStatePiece<byte[], ValueLocation> locationPiece,
				PcodeExecutorStatePiece<byte[], AddressSetView> readsPiece) {
			this.bytesPiece = bytesPiece;
			this.statePiece = statePiece;
			this.locationPiece = locationPiece;
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
		public WatchValuePcodeExecutorStatePiece fork() {
			return new WatchValuePcodeExecutorStatePiece(
				bytesPiece.fork(), statePiece.fork(), locationPiece.fork(), readsPiece.fork());
		}

		@Override
		public void setVar(AddressSpace space, byte[] offset, int size, boolean quantize,
				WatchValue val) {
			bytesPiece.setVar(space, offset, size, quantize, val.bytes.bytes);
			statePiece.setVar(space, offset, size, quantize, val.state);
			locationPiece.setVar(space, offset, size, quantize, val.location);
			readsPiece.setVar(space, offset, size, quantize, val.reads);
		}

		@Override
		public WatchValue getVar(AddressSpace space, byte[] offset, int size, boolean quantize,
				Reason reason) {
			return new WatchValue(
				new PrettyBytes(getLanguage().isBigEndian(),
					bytesPiece.getVar(space, offset, size, quantize, reason)),
				statePiece.getVar(space, offset, size, quantize, reason),
				locationPiece.getVar(space, offset, size, quantize, reason),
				readsPiece.getVar(space, offset, size, quantize, reason));
		}

		@Override
		public Map<Register, WatchValue> getRegisterValues() {
			Map<Register, WatchValue> result = new HashMap<>();
			for (Entry<Register, byte[]> entry : bytesPiece.getRegisterValues().entrySet()) {
				Register reg = entry.getKey();
				AddressSpace space = reg.getAddressSpace();
				long offset = reg.getAddress().getOffset();
				int size = reg.getNumBytes();
				result.put(reg, new WatchValue(
					new PrettyBytes(getLanguage().isBigEndian(), entry.getValue()),
					statePiece.getVar(space, offset, size, false, Reason.INSPECT),
					locationPiece.getVar(space, offset, size, false, Reason.INSPECT),
					readsPiece.getVar(space, offset, size, false, Reason.INSPECT)));
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
			statePiece.clear();
			locationPiece.clear();
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
		public WatchValuePcodeExecutorState fork() {
			return new WatchValuePcodeExecutorState(piece.fork());
		}

		@Override
		public void setVar(AddressSpace space, WatchValue offset, int size, boolean quantize,
				WatchValue val) {
			piece.setVar(space, offset.bytes.bytes, size, quantize, val);
		}

		@Override
		public WatchValue getVar(AddressSpace space, WatchValue offset, int size,
				boolean quantize,
				Reason reason) {
			return piece.getVar(space, offset.bytes.bytes, size, quantize, reason);
		}

		@Override
		public Map<Register, WatchValue> getRegisterValues() {
			return piece.getRegisterValues();
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
			new LocationPcodeExecutorStatePiece(data.getLanguage()),
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
