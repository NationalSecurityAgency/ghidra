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
import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.AbstractSimplePropertyBasedPieceHandler;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class ModelingScript extends GhidraScript {

	// ----------------------

	public static class JavaStdLibPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final AddressSpace space;
		private final Register regRSP;
		private final Register regRAX;
		private final Register regRDI;
		private final Register regRSI;

		public JavaStdLibPcodeUseropLibrary(SleighLanguage language) {
			space = language.getDefaultSpace();
			regRSP = language.getRegister("RSP");
			regRAX = language.getRegister("RAX");
			regRDI = language.getRegister("RDI");
			regRSI = language.getRegister("RSI");
		}

		@PcodeUserop
		public void __x86_64_RET(
				@OpExecutor PcodeExecutor<T> executor,
				@OpState PcodeExecutorState<T> state) {
			PcodeArithmetic<T> arithmetic = state.getArithmetic();
			T tRSP = state.getVar(regRSP, Reason.EXECUTE_READ);
			long lRSP = arithmetic.toLong(tRSP, Purpose.OTHER);
			T tReturn = state.getVar(space, lRSP, 8, true, Reason.EXECUTE_READ);
			long lReturn = arithmetic.toLong(tReturn, Purpose.BRANCH);
			state.setVar(regRSP, arithmetic.fromConst(lRSP + 8, 8));
			((PcodeThreadExecutor<T>) executor).getThread()
					.overrideCounter(space.getAddress(lReturn));
		}

		@PcodeUserop
		public void __libc_strlen(@OpState PcodeExecutorState<T> state) {
			PcodeArithmetic<T> arithmetic = state.getArithmetic();
			T tStr = state.getVar(regRDI, Reason.EXECUTE_READ);
			long lStr = arithmetic.toLong(tStr, Purpose.OTHER);
			T tMaxlen = state.getVar(regRSI, Reason.EXECUTE_READ);
			long lMaxlen = arithmetic.toLong(tMaxlen, Purpose.OTHER);

			for (int i = 0; i < lMaxlen; i++) {
				T tChar = state.getVar(space, lStr + i, 1, false, Reason.EXECUTE_READ);
				if (arithmetic.toLong(tChar, Purpose.OTHER) == 0) {
					state.setVar(regRAX, arithmetic.fromConst(Integer.toUnsignedLong(i), 8));
					break;
				}
			}
		}
	}

	// ----------------------

	public static class SleighStdLibPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private static final String SRC_RET = """
				RIP = *:8 RSP;
				RSP = RSP + 8;
				return [RIP];
				""";
		private static final String SRC_STRLEN = """
				__result = 0;
				<loop>
				if (*:1 (str+__result) == 0 || __result >= maxlen) goto <exit>;
				__result = __result + 1;
				goto <loop>;
				<exit>
				""";
		private final Register regRAX;
		private final Register regRDI;
		private final Register regRSI;
		private final Varnode vnRAX;
		private final Varnode vnRDI;
		private final Varnode vnRSI;

		private PcodeProgram progRet;
		private PcodeProgram progStrlen;

		public SleighStdLibPcodeUseropLibrary(SleighLanguage language) {
			regRAX = language.getRegister("RAX");
			regRDI = language.getRegister("RDI");
			regRSI = language.getRegister("RSI");
			vnRAX = new Varnode(regRAX.getAddress(), regRAX.getMinimumByteSize());
			vnRDI = new Varnode(regRDI.getAddress(), regRDI.getMinimumByteSize());
			vnRSI = new Varnode(regRSI.getAddress(), regRSI.getMinimumByteSize());
		}

		@PcodeUserop
		public void __x86_64_RET(@OpExecutor PcodeExecutor<T> executor,
				@OpLibrary PcodeUseropLibrary<T> library) {
			if (progRet == null) {
				progRet = SleighProgramCompiler.compileUserop(executor.getLanguage(),
					"__x86_64_RET", List.of(), SRC_RET, PcodeUseropLibrary.nil(), List.of());
			}
			progRet.execute(executor, library);
		}

		@PcodeUserop
		public void __libc_strlen(@OpExecutor PcodeExecutor<T> executor,
				@OpLibrary PcodeUseropLibrary<T> library) {
			if (progStrlen == null) {
				progStrlen = SleighProgramCompiler.compileUserop(executor.getLanguage(),
					"__libc_strlen", List.of("__result", "str", "maxlen"),
					SRC_STRLEN, PcodeUseropLibrary.nil(), List.of(vnRAX, vnRDI, vnRSI));
			}
			progStrlen.execute(executor, library);
		}
	}

	// ----------------------

	public static class StructuredStdLibPcodeUseropLibrary<T>
			extends AnnotatedPcodeUseropLibrary<T> {
		public StructuredStdLibPcodeUseropLibrary(CompilerSpec cs) {
			new MyStructuredPart(cs).generate(ops);
		}

		public static class MyStructuredPart extends StructuredSleigh {
			protected MyStructuredPart(CompilerSpec cs) {
				super(cs);
			}

			@StructuredUserop
			public void __x86_64_RET() {
				Var RSP = lang("RSP", type("void **"));
				Var RIP = lang("RIP", type("void *"));
				RIP.set(RSP.deref());
				RSP.addiTo(8);
				_return(RIP);
			}

			@StructuredUserop
			public void __libc_strlen() {
				Var result = lang("RAX", type("long"));
				Var str = lang("RDI", type("char *"));
				Var maxlen = lang("RSI", type("long"));

				_for(result.set(0), result.ltiu(maxlen).andb(str.index(result).deref().eq(0)),
					result.inc(), () -> {
					});
			}
		}
	}

	// ----------------------

	interface Expr {
		int size();
	}

	interface UnExpr extends Expr {
		Expr u();
	}

	interface BinExpr extends Expr {
		Expr l();

		Expr r();
	}

	record LitExpr(BigInteger val, int size) implements Expr {}

	record VarExpr(Varnode vn) implements Expr {
		public VarExpr(AddressSpace space, long offset, int size) {
			this(space.getAddress(offset), size);
		}

		public VarExpr(Address address, int size) {
			this(new Varnode(address, size));
		}

		@Override
		public int size() {
			return vn.getSize();
		}
	}

	record InvExpr(Expr u, int size) implements UnExpr {}

	record AddExpr(Expr l, Expr r, int size) implements BinExpr {}

	record SubExpr(Expr l, Expr r, int size) implements BinExpr {}

	// ----------------------

	public enum ExprPcodeArithmetic implements PcodeArithmetic<Expr> {
		BE(Endian.BIG), LE(Endian.LITTLE);

		public static ExprPcodeArithmetic forEndian(Endian endian) {
			return endian.isBigEndian() ? BE : LE;
		}

		public static ExprPcodeArithmetic forLanguage(Language language) {
			return language.isBigEndian() ? BE : LE;
		}

		private final Endian endian;

		private ExprPcodeArithmetic(Endian endian) {
			this.endian = endian;
		}

		@Override
		public Class<Expr> getDomain() {
			return Expr.class;
		}

		@Override
		public Endian getEndian() {
			return endian;
		}

		@Override
		public Expr unaryOp(int opcode, int sizeout, int sizein1, Expr in1) {
			return switch (opcode) {
				case PcodeOp.INT_NEGATE -> new InvExpr(in1, sizeout);
				default -> throw new UnsupportedOperationException(PcodeOp.getMnemonic(opcode));
			};
		}

		@Override
		public Expr binaryOp(int opcode, int sizeout, int sizein1, Expr in1, int sizein2,
				Expr in2) {
			return switch (opcode) {
				case PcodeOp.INT_ADD -> new AddExpr(in1, in2, sizeout);
				case PcodeOp.INT_SUB -> new SubExpr(in1, in2, sizeout);
				default -> throw new UnsupportedOperationException(PcodeOp.getMnemonic(opcode));
			};
		}

		@Override
		public Expr modBeforeStore(int sizeinOffset, AddressSpace space, Expr inOffset,
				int sizeinValue, Expr inValue) {
			return inValue;
		}

		@Override
		public Expr modAfterLoad(int sizeinOffset, AddressSpace space, Expr inOffset,
				int sizeinValue, Expr inValue) {
			return inValue;
		}

		@Override
		public Expr fromConst(byte[] value) {
			if (endian.isBigEndian()) {
				return new LitExpr(new BigInteger(1, value), value.length);
			}
			byte[] reversed = Arrays.copyOf(value, value.length);
			ArrayUtils.reverse(reversed);
			return new LitExpr(new BigInteger(1, reversed), reversed.length);
		}

		@Override
		public Expr fromConst(BigInteger value, int size, boolean isContextreg) {
			return new LitExpr(value, size);
		}

		@Override
		public Expr fromConst(long value, int size) {
			return fromConst(BigInteger.valueOf(value), size);
		}

		@Override
		public byte[] toConcrete(Expr value, Purpose purpose) {
			throw new UnsupportedOperationException();
		}

		@Override
		public long sizeOf(Expr value) {
			return value.size();
		}
	}

	// ----------------------

	public static class ExprSpace {
		protected final NavigableMap<Long, Expr> map = new TreeMap<>(Long::compareUnsigned);
		protected final ExprPcodeExecutorStatePiece piece;
		protected final AddressSpace space;

		protected ExprSpace(AddressSpace space, ExprPcodeExecutorStatePiece piece) {
			this.space = space;
			this.piece = piece;
		}

		public void clear() {
			map.clear();
		}

		public void set(long offset, int size, Expr val, PcodeStateCallbacks cb) {
			// TODO: Handle overlaps / offcut gets and sets
			map.put(offset, val);
			cb.dataWritten(piece, space.getAddress(offset), size, val);
		}

		public Expr get(long offset, int size, PcodeStateCallbacks cb) {
			// TODO: Handle overlaps / offcut gets and sets
			Expr expr = map.get(offset);
			if (expr == null) {
				byte[] aOffset =
					piece.getAddressArithmetic().fromConst(offset, space.getPointerSize());
				if (cb.readUninitialized(piece, space, aOffset, size) != 0) {
					return map.get(offset);
				}
			}
			return null;
		}

		public Entry<Long, Expr> getNextEntry(long offset) {
			return map.ceilingEntry(offset);
		}
	}

	public static class ExprPcodeExecutorStatePiece
			extends AbstractLongOffsetPcodeExecutorStatePiece<byte[], Expr, ExprSpace> {

		protected final Map<AddressSpace, ExprSpace> spaceMap = new HashMap<>();

		public ExprPcodeExecutorStatePiece(Language language, PcodeStateCallbacks cb) {
			super(language, BytesPcodeArithmetic.forLanguage(language),
				ExprPcodeArithmetic.forLanguage(language), cb);
		}

		@Override
		public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clear() {
			for (ExprSpace space : spaceMap.values()) {
				space.clear();
			}
		}

		@Override
		protected ExprSpace getForSpace(AddressSpace space, boolean toWrite) {
			if (toWrite) {
				return spaceMap.computeIfAbsent(space, s -> new ExprSpace(s, this));
			}
			return spaceMap.get(space);
		}

		@Override
		public Entry<Long, Expr> getNextEntryInternal(AddressSpace space, long offset) {
			ExprSpace s = getForSpace(space, false);
			if (s == null) {
				return null;
			}
			return s.getNextEntry(offset);
		}

		@Override
		protected void setInSpace(ExprSpace space, long offset, int size, Expr val,
				PcodeStateCallbacks cb) {
			space.set(offset, size, val, cb);
		}

		@Override
		protected Expr getFromSpace(ExprSpace space, long offset, int size, Reason reason,
				PcodeStateCallbacks cb) {
			return space.get(offset, size, cb);
		}

		@Override
		protected Map<Register, Expr> getRegisterValuesFromSpace(ExprSpace s,
				List<Register> registers) {
			throw new UnsupportedOperationException();
		}
	}

	public static class BytesExprPcodeExecutorState extends PairedPcodeExecutorState<byte[], Expr> {
		public BytesExprPcodeExecutorState(PcodeExecutorStatePiece<byte[], byte[]> concrete,
				PcodeStateCallbacks cb) {
			super(new PairedPcodeExecutorStatePiece<>(concrete,
				new ExprPcodeExecutorStatePiece(concrete.getLanguage(), cb)));
		}
	}

	// ----------------------

	public enum BytesExprEmulatorPartsFactory implements AuxEmulatorPartsFactory<Expr> {
		INSTANCE;

		@Override
		public PcodeArithmetic<Expr> getArithmetic(Language language) {
			return ExprPcodeArithmetic.forLanguage(language);
		}

		@Override
		public PcodeUseropLibrary<Pair<byte[], Expr>> createSharedUseropLibrary(
				AuxPcodeEmulator<Expr> emulator) {
			return PcodeUseropLibrary.nil();
		}

		@Override
		public PcodeUseropLibrary<Pair<byte[], Expr>> createLocalUseropStub(
				AuxPcodeEmulator<Expr> emulator) {
			return PcodeUseropLibrary.nil();
		}

		@Override
		public PcodeUseropLibrary<Pair<byte[], Expr>> createLocalUseropLibrary(
				AuxPcodeEmulator<Expr> emulator, PcodeThread<Pair<byte[], Expr>> thread) {
			return PcodeUseropLibrary.nil();
		}

		@Override
		public PcodeExecutorState<Pair<byte[], Expr>> createSharedState(
				AuxPcodeEmulator<Expr> emulator, BytesPcodeExecutorStatePiece concrete,
				PcodeStateCallbacks cb) {
			return new BytesExprPcodeExecutorState(concrete, cb);
		}

		@Override
		public PcodeExecutorState<Pair<byte[], Expr>> createLocalState(
				AuxPcodeEmulator<Expr> emulator, PcodeThread<Pair<byte[], Expr>> thread,
				BytesPcodeExecutorStatePiece concrete, PcodeStateCallbacks cb) {
			return new BytesExprPcodeExecutorState(concrete, cb);
		}
	}

	public static class BytesExprPcodeEmulator extends AuxPcodeEmulator<Expr> {
		public BytesExprPcodeEmulator(Language language,
				PcodeEmulationCallbacks<Pair<byte[], Expr>> cb) {
			super(language, cb);
		}

		public BytesExprPcodeEmulator(Language language) {
			this(language, PcodeEmulationCallbacks.none());
		}

		@Override
		protected AuxEmulatorPartsFactory<Expr> getPartsFactory() {
			return BytesExprEmulatorPartsFactory.INSTANCE;
		}
	}

	// ----------------------

	public static class ExprPieceHandler
			extends AbstractSimplePropertyBasedPieceHandler<byte[], Expr, String> {
		@Override
		public Class<byte[]> getAddressDomain() {
			return byte[].class;
		}

		@Override
		public Class<Expr> getValueDomain() {
			return Expr.class;
		}

		@Override
		protected String getPropertyName() {
			return "Expr";
		}

		@Override
		protected Class<String> getPropertyType() {
			return String.class;
		}

		@Override
		protected Expr decode(String propertyValue) {
			return Unfinished.TODO("Left as an exercise");
		}

		@Override
		protected String encode(Expr value) {
			return Unfinished.TODO("Left as an exercise");
		}
	}

	public static class BytesExprEmulatorFactory implements EmulatorFactory {
		@Override
		public String getTitle() {
			return "Expr";
		}

		@Override
		public PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer) {
			writer.putHandler(new ExprPieceHandler());
			return new BytesExprPcodeEmulator(access.getLanguage(), writer.callbacks());
		}
	}

	// ----------------------

	@Override
	protected void run() throws Exception {
		BytesExprPcodeEmulator emu = new BytesExprPcodeEmulator(currentProgram.getLanguage());
		// TODO: Initialize the machine
		PcodeExecutorState<Pair<byte[], Expr>> state = emu.getSharedState();
		state.setVar(currentAddress, 4, true,
			Pair.of(new byte[] { 1, 2, 3, 4 }, new VarExpr(currentAddress, 4)));
		PcodeThread<Pair<byte[], Expr>> thread = emu.newThread();
		// TODO: Initialize the thread
		while (true) {
			monitor.checkCancelled();
			thread.stepInstruction(100);
		}
	}
}
