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
package ghidra.pcode.emu.jit.analysis;

import static ghidra.pcode.emu.jit.analysis.JitVarScopeModel.maxAddr;

import java.math.BigInteger;
import java.util.*;

import org.objectweb.asm.Opcodes;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.alloc.*;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.util.Local;
import ghidra.pcode.emu.jit.gen.util.Scope;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.var.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Varnode;

/**
 * Type variable allocation phase for JIT-accelerated emulation.
 * 
 * <p>
 * The implements the Variable Allocation phase of the {@link JitCompiler} using a very simple
 * placement and another "voting" algorithm to decide the allocated JVM variable types. We place/map
 * variables by their storage varnodes, coalescing them as needed. Coalescing is performed for
 * overlapping, but not abutting varnodes. This allocation is anticipated by the
 * {@link JitVarScopeModel}, which performs the actual coalescing. Because multiple SSA variables
 * will almost certainly occupy the same varnode, we employ another voting system. For example, the
 * register {@code RAX} may be re-used many times within a passage. In some cases, it might be used
 * to return a floating-point value. In others (and <em>probably</em> more commonly) it will be used
 * to return an integral value. The more common case in the passage determines the JVM type of the
 * local variable allocated for {@code RAX}. Note that variables which occupy only part of a
 * coalesced varnode always vote for a JVM {@code int}, because of the shifting and masking required
 * to extract that part.
 * 
 * <p>
 * The allocation process is very simple, presuming successful type assignment:
 * 
 * <ol>
 * <li>Vote Tabulation</li>
 * <li>Index Reservation</li>
 * <li>Handler Creation</li>
 * </ol>
 * 
 * <h2>Vote Tabulation</h2>
 * <p>
 * Every SSA variable (excluding constants and memory variables) contributes a vote for the type of
 * its allocated local. If the varnode matches exactly, the vote is for the JVM type of the
 * variable's assigned p-code type. The type mapping is simple: For integral types, we allocate
 * using the smaller JVM type that fits the p-code type. For floating-point types, we allocate using
 * the JVM type that exactly matches the p-code type. If the varnode is larger, i.e., because it's
 * the result of coalescing, then the vote is for the smaller JVM integer type that fits the full
 * varnode. Consider the following p-code:
 * 
 * <pre>
 * 1. RAX = FLOAT_ADD RCX, RDX
 * 2. EAX = FLOAT_ADD EBX, 0x3f800000:4 # 1.0f
 * </pre>
 * 
 * <p>
 * Several values and variables are at play here. We tabulate the type assignments and resulting
 * votes:
 * 
 * <table border="1">
 * <tr>
 * <th>SSA Var</th>
 * <th>Type</th>
 * <th>Varnode</th>
 * <th>Vote</th>
 * </tr>
 * <tr>
 * <td>{@code RCX}<sub>in</sub></td>
 * <td>{@link DoubleJitType#F8 float8}</td>
 * <td>{@code RCX}</td>
 * <td>{@code double}</td>
 * </tr>
 * <tr>
 * <td>{@code RDX}<sub>in</sub></td>
 * <td>{@link DoubleJitType#F8 float8}</td>
 * <td>{@code RDX}</td>
 * <td>{@code double}</td>
 * </tr>
 * <tr>
 * <td>{@code RAX}<sub>1</sub></td>
 * <td>{@link DoubleJitType#F8 float8}</td>
 * <td>{@code RAX}</td>
 * <td>{@code double}</td>
 * </tr>
 * <tr>
 * <td>{@code EBX}<sub>in</sub></td>
 * <td>{@link FloatJitType#F4 float4}</td>
 * <td>{@code EBX}</td>
 * <td>{@code float}</td>
 * </tr>
 * <tr>
 * <td>{@code 0x3f800000:4}</td>
 * <td>{@link FloatJitType#F4 float4}</td>
 * </tr>
 * <tr>
 * <td>{@code EAX}<sub>2</sub></td>
 * <td>{@link FloatJitType#F4 float4}</td>
 * <td>{@code RAX}</td>
 * <td>{@code long}</td>
 * </tr>
 * </table>
 * 
 * The registers {@code RCX}, {@code RDX}, and {@code EBX} are trivially allocated as locals of JVM
 * types {@code double}, {@code double}, and {@code float}, respectively. It is also worth noting
 * that {@code 0x3f800000} is allocated as a {@code float} constant in the classfile's constant
 * pool. Now, we consider {@code RAX}. The varnodes for {@code RAX}<sub>1</sub> and
 * {@code EAX}<sub>2</sub> are coalesced to {@code RAX}. {@code RAX}<sub>1</sub> casts its vote for
 * {@code double}; whereas, {@code EAX}<sub>2</sub> casts its vote for {@code long}. This is because
 * placing {@code EAX}<sub>2</sub>'s value into the larger varnode requires bitwise operators, which
 * on the JVM, require integer operands. Thus the votes result in a tie, and favoring integral
 * types, we allocate {@code RAX} in a JVM {@code long}.
 * 
 * <h2>Index Reservation</h2>
 * <p>
 * After all the votes have been tabulated, we go through the results in address order, reserving
 * JVM local indices and assigning types. Note that we must reserve two indices for every variable
 * of type {@code long} or {@code double}, as specific by the JVM. Each of these reservations is
 * tracked in a {@link JvmLocal}. Note that index 0 is already reserved by the JVM for the
 * {@code this} ref, so we start our counting at 1. Also, some portions of the code generator may
 * need to allocate additional temporary locals, so we must allow access to the next free index
 * after all reservations are complete.
 * 
 * <h2>Handler Creation</h2>
 * <p>
 * This actually extends a little beyond allocation, but this is a suitable place for it: All SSA
 * values are assigned a handler, including constants and memory variables. Variables which access
 * the same varnode get the same handler. For varnodes that are allocated in a JVM local, we create
 * a handler that generates loads and stores to that local, e.g., {@link Opcodes#ILOAD iload}. For
 * constant varnodes, we create a handler that generates {@link Opcodes#LDC ldc} instructions. For
 * memory varnodes, we create a handler that generates a sequence of method invocations on the
 * {@link JitBytesPcodeExecutorState state}. The code generator will delegate to these handlers in
 * order to generate reads and writes of the corresponding variables, as well as to prepare any
 * resources to facilitate access, e.g., pre-fetching items from the
 * {@link JitBytesPcodeExecutorState state} in the generated constructor.
 * 
 * @implNote There are many artifacts below that anticipate supporting p-code types greater than 8
 *           bytes in size. One method to support that is to allocate multiple JVM locals per p-code
 *           varnode. Consider a 16-byte (128-bit) integer. We could allocate 4 JVM {@code int}
 *           locals and then emit bytecode that performs the gradeschool-style arithmetic. I suspect
 *           this would perform better than just using refs to {@link BigInteger}, because it avoids
 *           heap pollution, and also may avoid some unnecessary arithmetic, esp., for the more
 *           significant portions that get dropped.
 * @implNote <b>TODO</b>: It would be nice to detect varnode re-use under a different type and
 *           generate the appropriate declarations and handlers. This doesn't seem terribly complex,
 *           and it stands to spare us some casts. What's not clear is whether this offers any real
 *           run-time benefit.
 */
public class JitAllocationModel {

	/**
	 * The descriptor of a p-code variable
	 * 
	 * <p>
	 * This is just a logical grouping of a varnode and its assigned p-code type.
	 */
	private record VarDesc(int spaceId, long offset, int size, JitType type,
			Language language) {
		/**
		 * Create a descriptor from the given varnode and type
		 * 
		 * @param vn the varnode
		 * @param type the p-code type
		 * @param langauge the language
		 * @return the descriptor
		 */
		static VarDesc fromVarnode(Varnode vn, JitType type, Language language) {
			return new VarDesc(vn.getSpace(), vn.getOffset(), vn.getSize(), type, language);
		}

		/**
		 * Derive a name for this variable, to use in the name of allocated local(s)
		 * 
		 * @return the name
		 */
		public String name() {
			AddressFactory factory = language.getAddressFactory();
			AddressSpace space = factory.getAddressSpace(spaceId);
			Register reg = language.getRegister(space, offset, size);
			if (reg != null) {
				return "%s_%d_%s".formatted(reg.getName(), size, type.nm());
			}
			return "s%d_%x_%d_%s".formatted(spaceId, offset, size, type.nm());
		}

		/**
		 * Convert this descriptor back to a varnode
		 * 
		 * @return the varnode
		 */
		public Varnode toVarnode() {
			AddressFactory factory = language.getAddressFactory();
			return new Varnode(factory.getAddressSpace(spaceId).getAddress(offset), size);
		}
	}

	private final JitDataFlowModel dfm;
	private final JitVarScopeModel vsm;
	private final JitTypeModel tm;

	private final SleighLanguage language;
	private final Endian endian;

	private final Map<JitVal, VarHandler> handlers = new HashMap<>();
	private final Map<Varnode, VarHandler> handlersPerVarnode = new HashMap<>();
	private final NavigableMap<Address, JvmLocal<?, ?>> locals = new TreeMap<>();

	/**
	 * Construct the allocation model.
	 * 
	 * @param context the analysis context
	 * @param dfm the data flow model
	 * @param vsm the variable scope model
	 * @param tm the type model
	 */
	public JitAllocationModel(JitAnalysisContext context, JitDataFlowModel dfm,
			JitVarScopeModel vsm, JitTypeModel tm) {
		this.dfm = dfm;
		this.vsm = vsm;
		this.tm = tm;

		this.endian = context.getEndian();
		this.language = context.getLanguage();

		analyze();
	}

	/**
	 * Reserve (allocate) one local for the given p-code variable
	 * 
	 * @param name the name of the JVM local
	 * @param type the p-code type represented by the local
	 * @param desc the variable's descriptor
	 * @return the allocated JVM local
	 */
	private <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> JvmLocal<T, JT> declareLocal(
			Scope scope, JT type, String name, VarDesc desc) {
		Local<T> local = scope.decl(type.bType(), name);
		return JvmLocal.of(local, type, desc.toVarnode());
	}

	/**
	 * Reserve (allocate) several locals for the given p-code variable
	 * 
	 * @param name a prefix to name each JVM local
	 * @param types a p-code type that describes what each local stores
	 * @param desc the (whole) variable's descriptor
	 * @return the allocated JVM locals from most to least significant
	 */
	private <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> List<JvmLocal<T, JT>>
			declareLocals(Scope scope, List<JT> types, String name, VarDesc desc) {
		@SuppressWarnings("unchecked")
		JvmLocal<T, JT>[] result = new JvmLocal[types.size()];
		// assert types.stream().mapToInt(t -> t.size()).sum() == desc.size;
		long offset = desc.offset;
		for (int i = 0; i < types.size(); i++) {
			JT t = types.get(i);
			VarDesc d = new VarDesc(desc.spaceId, offset, t.size(), t, language);
			result[i] = declareLocal(scope, t, name + "_" + i, d);
			offset += t.size();
		}
		return List.of(result);
	}

	/**
	 * A content for assigning a type to a varnode
	 * 
	 * <p>
	 * Because several SSA variables can share one varnode, we let each cast a vote to determine the
	 * JVM type of the local(s) allocated to it.
	 * 
	 * @implNote <b>TODO</b>: This type contest could receive more detailed information from the
	 *           type model, but perhaps that's more work than it's worth. I would have to
	 *           communicate all votes, not just the winner....
	 */
	record TypeContest(Map<JitType, Integer> map) {
		/**
		 * Start a new contest
		 */
		public TypeContest() {
			this(new HashMap<>());
		}

		/**
		 * Cast a vote for the given type
		 * 
		 * @param type the type
		 */
		public void vote(JitType type) {
			map.compute(type.ext(), (t, v) -> v == null ? 1 : v + 1);
		}

		/**
		 * Choose the winner, favoring integral types
		 * 
		 * @return the winning type
		 */
		public JitType winner() {
			int max = map.values().stream().max(Integer::compare).get();
			return map.entrySet()
					.stream()
					.filter(e -> e.getValue() == max)
					.map(Map.Entry::getKey)
					.sorted(Comparator.comparing(JitType::pref))
					.findFirst()
					.get();
		}
	}

	private final Map<Varnode, TypeContest> typeContests = new HashMap<>();

	/**
	 * Create a handler for the variable stored by the one given local
	 * 
	 * @param local the local
	 * @return the handler
	 */
	@SuppressWarnings("unchecked")
	private <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> SimpleVarHandler<T, JT>
			createSimpleHandler(JvmLocal<T, JT> local) {
		return (SimpleVarHandler<T, JT>) switch (local.type()) {
			case IntJitType t -> new IntVarAlloc(local.castOf(t), t);
			case LongJitType t -> new LongVarAlloc(local.castOf(t), t);
			case FloatJitType t -> new FloatVarAlloc(local.castOf(t), t);
			case DoubleJitType t -> new DoubleVarAlloc(local.castOf(t), t);
			default -> throw new AssertionError();
		};
	}

	private int computeByteShift(Varnode part, Varnode first, Varnode last) {
		Varnode coalesced = vsm.getCoalesced(part);
		if (coalesced.equals(part)) {
			/**
			 * We could shift, but there's no point since there's no interplay with other varnodes.
			 */
			return 0;
		}
		return (int) switch (endian) {
			case BIG -> maxAddr(last).subtract(maxAddr(part));
			case LITTLE -> part.getAddress().subtract(first.getAddress());
		};
	}

	/**
	 * Create a handler for a multi-part or subpiece varnode
	 * 
	 * @param vn the varnode
	 * @return a handler to access the value of the given varnode, as allocated in one or more
	 *         locals.
	 */
	private VarHandler createComplicatedHandler(Varnode vn) {
		JitType type = JitTypeBehavior.INTEGER.type(vn.getSize());

		Map.Entry<Address, JvmLocal<?, ?>> firstEntry = locals.floorEntry(vn.getAddress());
		assert JitVarScopeModel.overlapsLeft(firstEntry.getValue().vn(), vn);

		if (type instanceof SimpleJitType<?, ?> st) {
			JvmLocal<?, ?> local = firstEntry.getValue();
			if (local.vn().contains(maxAddr(vn))) {
				int byteShift = computeByteShift(vn, local.vn(), local.vn());
				return switch (st) {
					case IntJitType t -> switch (local.type()) {
						case IntJitType ct -> new IntInIntHandler(local.castOf(ct), t, vn,
							byteShift);
						case LongJitType ct -> new IntInLongHandler(local.castOf(ct), t, vn,
							byteShift);
						default -> throw new AssertionError();
					};
					case LongJitType t -> switch (local.type()) {
						case LongJitType ct -> new LongInLongHandler(local.castOf(ct), t, vn,
							byteShift);
						default -> throw new AssertionError();
					};
					default -> throw new AssertionError();
				};
			}
		}

		/**
		 * NOTE: Type is not necessarily an MpIntJitType, but we are going to use an Aligned or
		 * Shifted MpIntHandler. They know how to load/store primitive types to/from the stack, too.
		 * We do need to select the equivalently-sized mp-int type, though, which is why we can't
		 * always assert mp-ints have more than 2 ints (exceed a long). They should have more than
		 * 1, though.
		 */
		MpIntJitType mpType = MpIntJitType.forSize(type.size());
		assert mpType.legsAlloc() > 1;

		List<JvmLocal<TInt, IntJitType>> parts = new ArrayList<>();
		Address min = firstEntry.getKey();
		NavigableMap<Address, JvmLocal<?, ?>> sub = locals.subMap(min, true, maxAddr(vn), true);
		for (JvmLocal<?, ?> local : sub.values()) {
			assert local.type() instanceof IntJitType;
			@SuppressWarnings("unchecked")
			var localInt = (JvmLocal<TInt, IntJitType>) local;
			parts.add(localInt);
		}
		int byteShift = computeByteShift(vn, parts.getFirst().vn(), parts.getLast().vn());
		/**
		 * All of the mp-int stuff assumes the lower-indexed legs are less significant, i.e.,
		 * they're given in little-endian order. We populated parts in order of address/offset. If
		 * the machine is little-endian, then they are already in the correct order. If the machine
		 * is big-endian, then we need to reverse them. (This seems opposite the usual intuition.)
		 */
		if (endian == Endian.BIG) {
			Collections.reverse(parts);
		}
		return byteShift == 0
				? new AlignedMpIntHandler(parts, mpType, vn)
				: new ShiftedMpIntHandler(parts, mpType, vn, byteShift);
	}

	/**
	 * Get (creating if necessary) the handler for the given variable's varnode.
	 * 
	 * @param vv the variable
	 * @return the handler
	 */
	private VarHandler getOrCreateHandlerForVarnodeVar(JitVarnodeVar vv) {
		return handlersPerVarnode.computeIfAbsent(vv.varnode(), vn -> {
			JvmLocal<?, ?> oneLocal = locals.get(vn.getAddress());
			if (oneLocal != null && oneLocal.vn().equals(vn)) {
				return createSimpleHandler(oneLocal);
			}
			return createComplicatedHandler(vn);
		});
	}

	/**
	 * Get (creating if necessary) the handler for the given value
	 * 
	 * @param v the value
	 * @return a handler for the value's varnode, if it is a register or unique; otherwise, the
	 *         dummy handler
	 */
	private VarHandler createHandler(JitVal v) {
		if (v instanceof JitConstVal) {
			return NoHandler.INSTANCE;
		}
		if (v instanceof JitFailVal) {
			return NoHandler.INSTANCE;
		}
		if (v instanceof JitMemoryVar) {
			return NoHandler.INSTANCE;
		}
		if (v instanceof JitVarnodeVar vv) {
			return getOrCreateHandlerForVarnodeVar(vv);
		}
		throw new AssertionError();
	}

	private void analyze() {
		for (JitVal v : dfm.allValues()) {
			if (v instanceof JitVarnodeVar vv && !(v instanceof JitMemoryVar)) {
				Varnode vn = vv.varnode();
				Varnode coalesced = vsm.getCoalesced(vn);
				TypeContest tc =
					typeContests.computeIfAbsent(coalesced, __ -> new TypeContest());
				if (vn.equals(coalesced)) {
					tc.vote(tm.typeOf(v));
				}
				else {
					tc.vote(JitTypeBehavior.INTEGER.type(coalesced.getSize()));
				}
			}
		}
	}

	/**
	 * Perform the actual allocations
	 * 
	 * @param scope the (probably root) scope for declaring the locals
	 */
	public void allocate(Scope scope) {
		for (Map.Entry<Varnode, TypeContest> entry : typeContests.entrySet()
				.stream()
				.sorted(Comparator.comparing(e -> e.getKey().getAddress()))
				.toList()) {
			VarDesc desc =
				VarDesc.fromVarnode(entry.getKey(), entry.getValue().winner(), language);
			switch (desc.type()) {
				case @SuppressWarnings("rawtypes") SimpleJitType t -> {
					@SuppressWarnings("unchecked")
					JvmLocal<?, ?> local = declareLocal(scope, t, desc.name(), desc);
					locals.put(entry.getKey().getAddress(), local);
				}
				case MpIntJitType t -> {
					for (JvmLocal<?, ?> leg : declareLocals(scope, t.legTypesBE(), desc.name(),
						desc)) {
						locals.put(leg.vn().getAddress(), leg);
					}
				}
				default -> throw new AssertionError();
			}
		}

		for (JitVal v : dfm.allValuesSorted()) {
			/**
			 * NOTE: We cannot cull outputs of synthetic ops here. Their outputs can (and usually
			 * are) consumed by real ops, and the values are assigned handlers by ref ID. Thus, the
			 * consuming op will need a handler for the synthetic op's output. We could consider
			 * keying the handlers some by an alternative (e.g., varnode when available), but that's
			 * for later exploration.
			 */
			handlers.put(v, createHandler(v));
		}
	}

	/**
	 * Get the handler for the given value (constant or variable in the use-def graph)
	 * 
	 * @param v the value
	 * @return the handler
	 */
	public VarHandler getHandler(JitVal v) {
		return handlers.get(v);
	}

	/**
	 * Get all of the locals allocated
	 * 
	 * @return the locals
	 */
	public Collection<JvmLocal<?, ?>> allLocals() {
		return locals.values();
	}

	/**
	 * Get all of the locals allocated for the given varnode
	 * 
	 * @implNote This is used by the code generator to birth and retire the local variables, given
	 *           that scope is analyzed in terms of varnodes.
	 * @param vn the varnode
	 * @return the locals
	 */
	public Collection<JvmLocal<?, ?>> localsForVn(Varnode vn) {
		Address min = vn.getAddress();
		Address floor = locals.floorKey(min);
		if (floor != null) {
			min = floor;
		}
		return locals.subMap(min, true, maxAddr(vn), true).values();
	}
}
