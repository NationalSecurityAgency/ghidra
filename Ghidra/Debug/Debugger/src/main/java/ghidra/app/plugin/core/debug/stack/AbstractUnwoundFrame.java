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
package ghidra.app.plugin.core.debug.stack;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.async.AsyncFence;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.eval.AbstractVarnodeEvaluator;
import ghidra.pcode.eval.ArithmeticVarnodeEvaluator;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.guest.TracePlatform;

/**
 * An abstract implementation of {@link UnwoundFrame}
 *
 * <p>
 * This generally contains all the methods for interpreting and retrieving higher-level variables
 * once the frame context is known. It doesn't contain the mechanisms for creating or reading
 * annotations.
 *
 * @param <T> the type of values retrievable from the unwound frame
 */
public abstract class AbstractUnwoundFrame<T> implements UnwoundFrame<T> {
	/**
	 * A class which can evaluate high p-code varnodes in the context of a stack frame using a
	 * p-code arithmetic
	 * 
	 * @param <U> the evaluation result type
	 */
	protected abstract class ArithmeticFrameVarnodeEvaluator<U>
			extends ArithmeticVarnodeEvaluator<U> {
		public ArithmeticFrameVarnodeEvaluator(PcodeArithmetic<U> arithmetic) {
			super(arithmetic);
		}

		@Override
		protected Address applyBase(long offset) {
			return AbstractUnwoundFrame.this.applyBase(offset);
		}

		@Override
		protected Address translateMemory(Program program, Address address) {
			TraceLocation location = mappingService.getOpenMappedLocation(trace,
				new ProgramLocation(program, address), snap);
			if (location == null) {
				throw new DynamicMappingException(program, address);
			}
			return location.getAddress();
		}
	}

	/**
	 * A class which can evaluate high p-code varnodes in the context of a stack frame
	 *
	 * @param <U> the evaluation result type
	 */
	protected abstract class AbstractFrameVarnodeEvaluator<U> extends AbstractVarnodeEvaluator<U> {
		@Override
		protected Address applyBase(long offset) {
			return AbstractUnwoundFrame.this.applyBase(offset);
		}

		@Override
		protected Address translateMemory(Program program, Address address) {
			TraceLocation location = mappingService.getOpenMappedLocation(trace,
				new ProgramLocation(program, address), snap);
			if (location == null) {
				throw new DynamicMappingException(program, address);
			}
			return location.getAddress();
		}
	}

	/**
	 * A frame evaluator which descends to symbol storage
	 * 
	 * <p>
	 * This ensure that if a register is used as a temporary value in an varnode AST, that
	 * evaluation proceeds all the way to the "source" symbols.
	 *
	 * @param <U> the evaluation result type
	 */
	protected abstract class FrameVarnodeEvaluator<U> extends ArithmeticFrameVarnodeEvaluator<U> {
		private final AddressSetView symbolStorage;

		/**
		 * Construct an evaluator with the given arithmetic and symbol storage
		 * 
		 * <p>
		 * Varnodes contained completely in symbol storage are presumed to be the inputs of the
		 * evaluation. All other varnodes are evaluated by examining their defining p-code op. It is
		 * an error to include any unique space in symbol storage.
		 * 
		 * @param arithmetic the arithmetic for evaluating p-code ops
		 * @param symbolStorage the address ranges to regard as input, i.e., the leaves of evalution
		 */
		public FrameVarnodeEvaluator(PcodeArithmetic<U> arithmetic, AddressSetView symbolStorage) {
			super(arithmetic);
			this.symbolStorage = symbolStorage;
		}

		@Override
		protected boolean isLeaf(Varnode vn) {
			if (vn.getDef() == null && (vn.isRegister() || vn.isAddress())) {
				return true;
			}
			return vn.isConstant() ||
				symbolStorage.contains(vn.getAddress(), vn.getAddress().add(vn.getSize() - 1));
		}
	}

	/**
	 * A frame "evaluator" which merely gets values
	 *
	 * <p>
	 * This evaluator never descends to defining p-code ops. It is an error to ask it for the value
	 * of unique varnodes. With some creativity, this can also be used as a varnode visitor to set
	 * values.
	 *
	 * @param <U> the evaluation result type
	 */
	protected abstract class FrameVarnodeValueGetter<U> extends ArithmeticFrameVarnodeEvaluator<U> {
		public FrameVarnodeValueGetter(PcodeArithmetic<U> arithmetic) {
			super(arithmetic);
		}

		@Override
		protected boolean isLeaf(Varnode vn) {
			return true;
		}
	}

	/**
	 * A frame "evaluator" which actually sets values
	 * 
	 * @param <U> the evaluation result type
	 */
	protected abstract class FrameVarnodeValueSetter<U> extends AbstractFrameVarnodeEvaluator<U> {
		@Override
		protected boolean isLeaf(Varnode vn) {
			return true;
		}

		@Override
		protected U evaluateUnaryOp(Program program, PcodeOp op, UnaryOpBehavior unOp,
				Map<Varnode, U> already) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected U evaluateBinaryOp(Program program, PcodeOp op, BinaryOpBehavior binOp,
				Map<Varnode, U> already) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected U evaluateAbstract(Program program, AddressSpace space, U offset, int size,
				Map<Varnode, U> already) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected U evaluateConstant(long value, int size) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected U evaluateLoad(Program program, PcodeOp op, Map<Varnode, U> already) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected U evaluatePtrAdd(Program program, PcodeOp op, Map<Varnode, U> already) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected U evaluatePtrSub(Program program, PcodeOp op, Map<Varnode, U> already) {
			throw new UnsupportedOperationException();
		}
	}

	protected final DebuggerCoordinates coordinates;
	protected final Trace trace;
	protected final TracePlatform platform;
	protected final long snap;
	protected final long viewSnap;
	protected final Language language;
	protected final AddressSpace codeSpace;
	protected final Register pc;
	protected final PcodeExecutorState<T> state;

	protected final DebuggerStaticMappingService mappingService;

	/**
	 * Construct an unwound frame
	 * 
	 * @param tool the tool requesting interpretation of the frame, which provides context for
	 *            mapped static programs.
	 * @param coordinates the coordinates (trace, thread, snap, etc.) to examine
	 * @param state the machine state, typically the watch value state for the same coordinates. It
	 *            is the caller's (i.e., subclass') responsibility to ensure the given state
	 *            corresponds to the given coordinates.
	 */
	public AbstractUnwoundFrame(PluginTool tool, DebuggerCoordinates coordinates,
			PcodeExecutorState<T> state) {
		this.coordinates = coordinates;
		this.trace = coordinates.getTrace();
		this.platform = coordinates.getPlatform();
		this.snap = coordinates.getSnap();
		this.viewSnap = coordinates.getViewSnap();
		this.language = platform.getLanguage();
		this.codeSpace = language.getDefaultSpace();
		this.pc = language.getProgramCounter();

		this.state = state;
		this.mappingService = tool.getService(DebuggerStaticMappingService.class);
	}

	/**
	 * Get or recover the saved register map
	 * 
	 * <p>
	 * This indicates the location of saved registers on the stack that apply to this frame.
	 * 
	 * @return the register map
	 */
	protected abstract SavedRegisterMap computeRegisterMap();

	/**
	 * Compute the <em>address of</em> the return address
	 * 
	 * @return the address of the return address
	 */
	protected abstract Address computeAddressOfReturnAddress();

	/**
	 * Compute the address (in physical stack space) of the given stack offset
	 * 
	 * @param offset the stack offset, relative to the stack pointer at the entry to the function
	 *            that allocated this frame.
	 * @return the address in physical stack space
	 */
	protected abstract Address applyBase(long offset);

	@Override
	public T getValue(Program program, VariableStorage storage) {
		SavedRegisterMap registerMap = computeRegisterMap();
		return new FrameVarnodeValueGetter<T>(state.getArithmetic()) {
			@Override
			protected T evaluateMemory(Address address, int size) {
				return registerMap.getVar(state, address, size, Reason.INSPECT);
			}
		}.evaluateStorage(program, storage);
	}

	@Override
	public T getValue(Register register) {
		SavedRegisterMap registerMap = computeRegisterMap();
		return registerMap.getVar(state, register.getAddress(), register.getNumBytes(),
			Reason.INSPECT);
	}

	@Override
	public T evaluate(Program program, VariableStorage storage, AddressSetView symbolStorage) {
		SavedRegisterMap registerMap = computeRegisterMap();
		return new FrameVarnodeEvaluator<T>(state.getArithmetic(), symbolStorage) {
			@Override
			protected T evaluateMemory(Address address, int size) {
				return registerMap.getVar(state, address, size, Reason.INSPECT);
			}
		}.evaluateStorage(program, storage);
	}

	@Override
	public T evaluate(Program program, PcodeOp op, AddressSetView symbolStorage) {
		SavedRegisterMap registerMap = computeRegisterMap();
		return new FrameVarnodeEvaluator<T>(state.getArithmetic(), symbolStorage) {
			@Override
			protected T evaluateMemory(Address address, int size) {
				return registerMap.getVar(state, address, size, Reason.INSPECT);
			}
		}.evaluateOp(program, op);
	}

	@Override
	public CompletableFuture<Void> setValue(StateEditor editor, Program program,
			VariableStorage storage, BigInteger value) {
		SavedRegisterMap registerMap = computeRegisterMap();
		ByteBuffer buf = ByteBuffer.wrap(Utils.bigIntegerToBytes(value, storage.size(), true));
		AsyncFence fence = new AsyncFence();
		new FrameVarnodeValueSetter<ByteBuffer>() {
			@Override
			protected ByteBuffer evaluateMemory(Address address, int size) {
				byte[] bytes = new byte[size];
				buf.get(bytes);
				if (!language.isBigEndian()) {
					ArrayUtils.reverse(bytes);
				}
				fence.include(registerMap.setVar(editor, address, bytes));
				return buf;
			}

			@Override
			protected ByteBuffer catenate(int total, ByteBuffer value, ByteBuffer piece, int size) {
				return value;
			}

			@Override
			public ByteBuffer evaluateStorage(Program program, VariableStorage storage) {
				return evaluateStorage(program, storage, buf);
			}
		}.evaluateStorage(program, storage);
		return fence.ready();
	}

	@Override
	public CompletableFuture<Void> setReturnAddress(StateEditor editor, Address addr) {
		if (addr.getAddressSpace() != codeSpace) {
			throw new IllegalArgumentException("Return address must be in " + codeSpace);
		}
		BytesPcodeArithmetic bytesArithmetic = BytesPcodeArithmetic.forLanguage(language);
		byte[] bytes = bytesArithmetic.fromConst(addr.getOffset(), pc.getNumBytes());
		return editor.setVariable(computeAddressOfReturnAddress(), bytes);
	}

	@Override
	public T zext(T value, int length) {
		PcodeArithmetic<T> arithmetic = state.getArithmetic();
		return arithmetic.unaryOp(PcodeOp.INT_ZEXT, length, (int) arithmetic.sizeOf(value), value);
	}
}
