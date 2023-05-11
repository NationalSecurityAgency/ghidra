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

import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerPcodeEmulator;
import ghidra.pcode.exec.trace.*;
import ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
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
	}

	interface UnExpr extends Expr {
		Expr u();
	}

	interface BinExpr extends Expr {
		Expr l();

		Expr r();
	}

	record LitExpr(BigInteger val, int size) implements Expr {
	}

	record VarExpr(Varnode vn) implements Expr {
		public VarExpr(AddressSpace space, long offset, int size) {
			this(space.getAddress(offset), size);
		}

		public VarExpr(Address address, int size) {
			this(new Varnode(address, size));
		}
	}

	record InvExpr(Expr u) implements UnExpr {
	}

	record AddExpr(Expr l, Expr r) implements BinExpr {
	}

	record SubExpr(Expr l, Expr r) implements BinExpr {
	}

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
		public Endian getEndian() {
			return endian;
		}

		@Override
		public Expr unaryOp(int opcode, int sizeout, int sizein1, Expr in1) {
			return switch (opcode) {
				case PcodeOp.INT_NEGATE -> new InvExpr(in1);
				default -> throw new UnsupportedOperationException(PcodeOp.getMnemonic(opcode));
			};
		}

		@Override
		public Expr binaryOp(int opcode, int sizeout, int sizein1, Expr in1, int sizein2,
				Expr in2) {
			return switch (opcode) {
				case PcodeOp.INT_ADD -> new AddExpr(in1, in2);
				case PcodeOp.INT_SUB -> new SubExpr(in1, in2);
				default -> throw new UnsupportedOperationException(PcodeOp.getMnemonic(opcode));
			};
		}

		@Override
		public Expr modBeforeStore(int sizeout, int sizeinAddress, Expr inAddress, int sizeinValue,
				Expr inValue) {
			return inValue;
		}

		@Override
		public Expr modAfterLoad(int sizeout, int sizeinAddress, Expr inAddress, int sizeinValue,
				Expr inValue) {
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
			throw new UnsupportedOperationException();
		}
	}

	// ----------------------

	public static class ExprSpace {
		protected final NavigableMap<Long, Expr> map;
		protected final AddressSpace space;

		protected ExprSpace(AddressSpace space, NavigableMap<Long, Expr> map) {
			this.space = space;
			this.map = map;
		}

		public ExprSpace(AddressSpace space) {
			this(space, new TreeMap<>());
		}

		public void clear() {
			map.clear();
		}

		public void set(long offset, Expr val) {
			// TODO: Handle overlaps / offcut gets and sets
			map.put(offset, val);
		}

		public Expr get(long offset, int size) {
			// TODO: Handle overlaps / offcut gets and sets
			Expr expr = map.get(offset);
			return expr != null ? expr : whenNull(offset, size);
		}

		protected Expr whenNull(long offset, int size) {
			return new VarExpr(space, offset, size);
		}
	}

	public static abstract class AbstractBytesExprPcodeExecutorStatePiece<S extends ExprSpace>
			extends
			AbstractLongOffsetPcodeExecutorStatePiece<byte[], Expr, S> {

		protected final AbstractSpaceMap<S> spaceMap = newSpaceMap();

		public AbstractBytesExprPcodeExecutorStatePiece(Language language) {
			super(language, BytesPcodeArithmetic.forLanguage(language),
				ExprPcodeArithmetic.forLanguage(language));
		}

		protected abstract AbstractSpaceMap<S> newSpaceMap();

		@Override
		public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clear() {
			for (S space : spaceMap.values()) {
				space.clear();
			}
		}

		@Override
		protected S getForSpace(AddressSpace space, boolean toWrite) {
			return spaceMap.getForSpace(space, toWrite);
		}

		@Override
		protected void setInSpace(ExprSpace space, long offset, int size, Expr val) {
			space.set(offset, val);
		}

		@Override
		protected Expr getFromSpace(S space, long offset, int size, Reason reason) {
			return space.get(offset, size);
		}

		@Override
		protected Map<Register, Expr> getRegisterValuesFromSpace(S s, List<Register> registers) {
			throw new UnsupportedOperationException();
		}
	}

	public static class ExprPcodeExecutorStatePiece
			extends AbstractBytesExprPcodeExecutorStatePiece<ExprSpace> {
		public ExprPcodeExecutorStatePiece(Language language) {
			super(language);
		}

		@Override
		protected AbstractSpaceMap<ExprSpace> newSpaceMap() {
			return new SimpleSpaceMap<ExprSpace>() {
				@Override
				protected ExprSpace newSpace(AddressSpace space) {
					return new ExprSpace(space);
				}
			};
		}
	}

	public static class BytesExprPcodeExecutorState extends PairedPcodeExecutorState<byte[], Expr> {
		public BytesExprPcodeExecutorState(PcodeExecutorStatePiece<byte[], byte[]> concrete) {
			super(new PairedPcodeExecutorStatePiece<>(concrete,
				new ExprPcodeExecutorStatePiece(concrete.getLanguage())));
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
				AuxPcodeEmulator<Expr> emulator, BytesPcodeExecutorStatePiece concrete) {
			return new BytesExprPcodeExecutorState(concrete);
		}

		@Override
		public PcodeExecutorState<Pair<byte[], Expr>> createLocalState(
				AuxPcodeEmulator<Expr> emulator, PcodeThread<Pair<byte[], Expr>> thread,
				BytesPcodeExecutorStatePiece concrete) {
			return new BytesExprPcodeExecutorState(concrete);
		}
	}

	public class BytesExprPcodeEmulator extends AuxPcodeEmulator<Expr> {
		public BytesExprPcodeEmulator(Language language) {
			super(language);
		}

		@Override
		protected AuxEmulatorPartsFactory<Expr> getPartsFactory() {
			return BytesExprEmulatorPartsFactory.INSTANCE;
		}
	}

	// ----------------------

	public static class ExprTraceSpace extends ExprSpace {
		protected final PcodeTracePropertyAccess<String> property;

		public ExprTraceSpace(AddressSpace space, PcodeTracePropertyAccess<String> property) {
			super(space);
			this.property = property;
		}

		@Override
		protected Expr whenNull(long offset, int size) {
			String string = property.get(space.getAddress(offset));
			return deserialize(string);
		}

		public void writeDown(PcodeTracePropertyAccess<String> into) {
			if (space.isUniqueSpace()) {
				return;
			}

			for (Entry<Long, Expr> entry : map.entrySet()) {
				// TODO: Ignore and/or clear non-entries
				into.put(space.getAddress(entry.getKey()), serialize(entry.getValue()));
			}
		}

		protected String serialize(Expr expr) {
			return Unfinished.TODO();
		}

		protected Expr deserialize(String string) {
			return Unfinished.TODO();
		}
	}

	public static class BytesExprTracePcodeExecutorStatePiece
			extends AbstractBytesExprPcodeExecutorStatePiece<ExprTraceSpace>
			implements TracePcodeExecutorStatePiece<byte[], Expr> {
		public static final String NAME = "Taint";

		protected final PcodeTraceDataAccess data;
		protected final PcodeTracePropertyAccess<String> property;

		public BytesExprTracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
			super(data.getLanguage());
			this.data = data;
			this.property = data.getPropertyAccess(NAME, String.class);
		}

		@Override
		public PcodeTraceDataAccess getData() {
			return data;
		}

		@Override
		protected AbstractSpaceMap<ExprTraceSpace> newSpaceMap() {
			return new CacheingSpaceMap<PcodeTracePropertyAccess<String>, ExprTraceSpace>() {
				@Override
				protected PcodeTracePropertyAccess<String> getBacking(AddressSpace space) {
					return property;
				}

				@Override
				protected ExprTraceSpace newSpace(AddressSpace space,
						PcodeTracePropertyAccess<String> backing) {
					return new ExprTraceSpace(space, property);
				}
			};
		}

		@Override
		public BytesExprTracePcodeExecutorStatePiece fork() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeDown(PcodeTraceDataAccess into) {
			PcodeTracePropertyAccess<String> property = into.getPropertyAccess(NAME, String.class);
			for (ExprTraceSpace space : spaceMap.values()) {
				space.writeDown(property);
			}
		}
	}

	public static class BytesExprTracePcodeExecutorState
			extends PairedTracePcodeExecutorState<byte[], Expr> {

		public BytesExprTracePcodeExecutorState(
				TracePcodeExecutorStatePiece<byte[], byte[]> concrete) {
			super(new PairedTracePcodeExecutorStatePiece<>(concrete,
				new BytesExprTracePcodeExecutorStatePiece(concrete.getData())));
		}
	}

	enum BytesExprDebuggerEmulatorPartsFactory implements AuxDebuggerEmulatorPartsFactory<Expr> {
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
				AuxPcodeEmulator<Expr> emulator,
				PcodeThread<Pair<byte[], Expr>> thread) {
			return PcodeUseropLibrary.nil();
		}

		@Override
		public PcodeExecutorState<Pair<byte[], Expr>> createSharedState(
				AuxPcodeEmulator<Expr> emulator,
				BytesPcodeExecutorStatePiece concrete) {
			return new BytesExprPcodeExecutorState(concrete);
		}

		@Override
		public PcodeExecutorState<Pair<byte[], Expr>> createLocalState(
				AuxPcodeEmulator<Expr> emulator,
				PcodeThread<Pair<byte[], Expr>> thread,
				BytesPcodeExecutorStatePiece concrete) {
			return new BytesExprPcodeExecutorState(concrete);
		}

		@Override
		public TracePcodeExecutorState<Pair<byte[], Expr>> createTraceSharedState(
				AuxTracePcodeEmulator<Expr> emulator,
				BytesTracePcodeExecutorStatePiece concrete) {
			return new BytesExprTracePcodeExecutorState(concrete);
		}

		@Override
		public TracePcodeExecutorState<Pair<byte[], Expr>> createTraceLocalState(
				AuxTracePcodeEmulator<Expr> emulator,
				PcodeThread<Pair<byte[], Expr>> thread,
				BytesTracePcodeExecutorStatePiece concrete) {
			return new BytesExprTracePcodeExecutorState(concrete);
		}

		@Override
		public TracePcodeExecutorState<Pair<byte[], Expr>> createDebuggerSharedState(
				AuxDebuggerPcodeEmulator<Expr> emulator,
				RWTargetMemoryPcodeExecutorStatePiece concrete) {
			return new BytesExprTracePcodeExecutorState(concrete);
		}

		@Override
		public TracePcodeExecutorState<Pair<byte[], Expr>> createDebuggerLocalState(
				AuxDebuggerPcodeEmulator<Expr> emulator,
				PcodeThread<Pair<byte[], Expr>> thread,
				RWTargetRegistersPcodeExecutorStatePiece concrete) {
			return new BytesExprTracePcodeExecutorState(concrete);
		}
	}

	public static class BytesExprDebuggerPcodeEmulator extends AuxDebuggerPcodeEmulator<Expr> {
		public BytesExprDebuggerPcodeEmulator(PcodeDebuggerAccess access) {
			super(access);
		}

		@Override
		protected AuxDebuggerEmulatorPartsFactory<Expr> getPartsFactory() {
			return BytesExprDebuggerEmulatorPartsFactory.INSTANCE;
		}
	}

	public static class BytesExprDebuggerPcodeEmulatorFactory
			implements DebuggerPcodeEmulatorFactory {

		@Override
		public String getTitle() {
			return "Expr";
		}

		@Override
		public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
			return new BytesExprDebuggerPcodeEmulator(access);
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
