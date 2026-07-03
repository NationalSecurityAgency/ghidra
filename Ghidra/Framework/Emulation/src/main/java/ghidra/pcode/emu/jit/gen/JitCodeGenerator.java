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
package ghidra.pcode.emu.jit.gen;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;
import static org.objectweb.asm.Opcodes.*;

import java.io.*;
import java.lang.invoke.MethodHandles.Lookup;
import java.util.*;
import java.util.stream.Stream;

import org.apache.commons.lang3.reflect.TypeLiteral;
import org.objectweb.asm.*;
import org.objectweb.asm.util.TraceClassVisitor;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.alloc.JvmLocal;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.op.IntMultOpGen;
import ghidra.pcode.emu.jit.gen.op.OpGen;
import ghidra.pcode.emu.jit.gen.op.OpGen.*;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.gen.var.ValGen;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.gen.var.VarGen.BlockTransition;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.emu.jit.var.JitVar;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.pcode.exec.SleighPcodeUseropDefinition;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

/**
 * The bytecode generator for JIT-accelerated emulation.
 * 
 * <p>
 * This implements the Code Generation phase of the {@link JitCompiler}. With all the prior
 * analysis, code generation is just a careful process of visiting all of the ops, variables, and
 * analytic results to ensure everything is incorporated and accounted for.
 * 
 * <h2>The Target Classfile</h2>
 * <p>
 * The target is a classfile that implements {@link JitCompiledPassage}. As such, it must implement
 * all of the specified methods in that interface as well as a constructor having a specific
 * {@link JitCompiledPassageClass#CONSTRUCTOR_TYPE signature}. That signature takes a
 * {@link JitPcodeThread} and, being a constructor, returns {@code void}. We will also need to
 * generate a static initializer to populate some metadata and pre-fetch any static things, e.g.,
 * the {@link SleighLanguage} for the emulation target. The fields are:
 * 
 * <ul>
 * <li><b>{@code static }{@link String}{@code  LANGUAGE_ID}</b> - The language ID (as in
 * {@link LanguageID} of the emulation target</li>
 * <li><b>{@code static }{@link Language}{@code  LANGUAGE}</b> - The language (ISA) of the emulation
 * target</li>
 * <li><b>{@code static }{@link AddressFactory}{@code  ADDRESS_FACTORY}</b> - The address factory of
 * the language</li>
 * <li><b>{@code static }{@link List}{@code <}{@link AddrCtx}{@code > ENTRIES}</b> - The list of
 * entry points</li>
 * <li><b>{@link JitPcodeThread}{@code  thread}</b> - The bound thread for this instance of the
 * compiled passage</li>
 * <li><b>{@link JitBytesPcodeExecutorState}{@code  state}</b> - The run-time machine state for this
 * thread of emulation</li>
 * </ul>
 * 
 * <h3>Static Initializer</h3>
 * <p>
 * In the Java language, statements in a class's {@code static} block, as well as the initial values
 * of static fields are implemented by the classfile's {@code <clinit>} method. We use it to
 * pre-construct {@code contextreg} values and {@link Varnode varnode} refs for use in birthing and
 * retirement. They are kept in static fields. We also initialize the static {@code ENTRIES} field,
 * which is public (via reflection) and describes each entry point generated. It has the type
 * {@code List<}{@link AddrCtx}{@code >}. A call to {@link JitCompiledPassage#run(int)} should pass
 * in the position of the desired entry point in the {@code ENTRIES} list.
 * 
 * <h3>Constructor</h3>
 * <p>
 * In the Java language, statements in a class's constructor, as well as the initial values of
 * instance fields are implemented by the classfile's {@code <init>} methods. We provide a single
 * constructor that accepts a {@link JitPcodeThread}. Upon construction, the generated
 * {@link JitCompiledPassage} is "bound" to the given thread. The constructor pre-fetches parts of
 * the thread's {@link JitBytesPcodeExecutorState state} and {@link SleighPcodeUseropDefinition
 * userop definitions}, and it allocates {@link ExitSlot}s. Each of these are kept in instance
 * fields.
 * 
 * <h3>{@code thread()} Method</h3>
 * <p>
 * This method implements {@link JitCompiledPassage#thread()}, a simple getter for the
 * {@code thread} field.
 * 
 * <h3>{@code run()} Method</h3>
 * <p>
 * This method implements {@link JitCompiledPassage#run(int)}, the actual semantics of the
 * translated machine instructions selected for the passage. It accepts a single parameter, which is
 * the position in the {@code ENTRIES} list of the desired entry point {@code blockId}. The
 * structure is as follows:
 * 
 * <ol>
 * <li>Entry point dispatch - a large {@code switch} statement on the entry {@code blockId}</li>
 * <li>P-code translation - the block-by-block op-by-op translation of the p-code to bytecode</li>
 * <li>Exception handlers - exception handlers as requested by various elements of the p-code
 * translation</li>
 * <li>Parameter declarations - {@code this} and {@code blockId}</li>
 * <li>Allocated local declarations - declares all locals allocated by
 * {@link JitAllocationModel}</li>
 * </ol>
 * 
 * <h4>Entry Point Dispatch</h4>
 * <p>
 * This part of the run method dispatches execution to the correct entry point within the translated
 * passage. It consists of these sub-parts:
 * 
 * <ol>
 * <li>Switch table - a {@link Opcodes#TABLESWITCH tableswitch} to jump to the code for the scope
 * transition into the entry block given by {@code blockId}</li>
 * <li>Scope transitions - for each block, birth its live varnodes then jump to the block's
 * translation</li>
 * <li>Default case - throws an {@link IllegalArgumentException} for an invalid {@code blockId}</li>
 * </ol>
 * 
 * <p>
 * This first ensure that a valid entry point was given in {@code blockId}. If not, we jump to the
 * default case which throws an exception. Otherwise, we jump to the appropriate entry transition.
 * Every block flow edge is subject to a scope transition wherein varnodes that leave scope must be
 * retired and varnodes that enter scope must be birthed. We generate an entry transition for each
 * possible entry block. That transition births all the varnodes that are in scope for that entry
 * block then jumps to the entry block's p-code translation.
 * 
 * <h4>P-code Translation</h4>
 * <p>
 * Here, most of the generation is performed via delegation to an object model, based on the use-def
 * graph. We first iterate over the blocks, in the same order as they appear in the decoded passage.
 * This will ensure that fall-through control transitions in the p-code map to fall-through
 * transitions in the emitted bytecode. If the block is the target of a bytecode jump, i.e., it's an
 * entry block or the target of a p-code branch, then we emit a label at the start of the block. We
 * then iterate over each p-code op in the block delegating each to the appropriate generator. We
 * emit "line number" information for each op to help debug crashes. A generator may register an
 * exception handler to be emitted later in the "exception handlers" part of the {@code run} method.
 * If the block has fall through, we emit the appropriate scope transition before proceeding to the
 * next block. Note that scope transitions for branch ops are emitted by the generators for those
 * ops.
 * 
 * <p>
 * For details about individual p-code op translations, see {@link OpGen}. For details about
 * individual SSA value (constant and variable) translations, see {@link VarGen}. For details about
 * emitting scope transitions, see {@link BlockTransition}.
 * 
 * @implNote Throughout most of the code that emits bytecode, there are (human-generated) comments
 *           to track the contents of the JVM stack. Items pushed onto the stack appear at the
 *           right. If type is important, then those are denoted using :TYPE after the relevant
 *           variable. TODO: It'd be nice to have a bytecode API that enforces stack structure using
 *           the compiler (somehow), but that's probably overkill. Also, I have yet to see what the
 *           official classfile API will bring.
 * @param <THIS> the type of the generated passage
 */
public class JitCodeGenerator<THIS extends JitCompiledPassage> {
	/**
	 * The key for a varnode, to ensure we control the definition of {@link Object#equals(Object)
	 * equality}.
	 */
	record VarnodeKey(int space, long offset, int size) {
		/**
		 * Extract/construct the key for a given varnode
		 * 
		 * @param vn the varnode
		 */
		public VarnodeKey(Varnode vn) {
			this(vn == null ? 0 : vn.getSpace(), vn == null ? 0 : vn.getOffset(),
				vn == null ? 0 : vn.getSize());
		}
	}

	/**
	 * The key for a p-code op, to ensure we control "equality"
	 */
	record PcodeOpKey(VarnodeKey out, int opcode, List<VarnodeKey> ins) {
		/**
		 * Extract/construct thhe key for a given op
		 * 
		 * @param op the p-code op
		 */
		public PcodeOpKey(PcodeOp op) {
			this(new VarnodeKey(op.getOutput()), op.getOpcode(),
				Stream.of(op.getInputs()).map(VarnodeKey::new).toList());
		}
	}

	private final Lookup lookup;
	final JitAnalysisContext context;
	final JitControlFlowModel cfm;
	final JitDataFlowModel dfm;
	final JitVarScopeModel vsm;
	final JitTypeModel tm;
	final JitAllocationModel am;
	final JitOpUseModel oum;

	private final Map<JitBlock, Lbl<Bot>> blockLabels = new HashMap<>();

	private final Map<PcodeOp, ExceptionHandler> excHandlers = new LinkedHashMap<>();

	private final Map<AddressSpace, FieldForSpaceIndirect> fieldsForSpaceIndirect = new HashMap<>();
	private final Map<Address, FieldForArrDirect> fieldsForArrDirect = new HashMap<>();
	private final Map<RegisterValue, FieldForContext> fieldsForContext = new HashMap<>();
	private final Map<VarnodeKey, FieldForVarnode> fieldsForVarnode = new HashMap<>();
	private final Map<PcodeOpKey, FieldForPcodeOp> fieldsForOp = new HashMap<>();
	private final Map<String, FieldForUserop> fieldsForUserop = new HashMap<>();
	private final Map<AddrCtx, FieldForExitSlot> fieldsForExitSlot = new HashMap<>();

	final String nameThis;
	final TRef<THIS> typeThis;

	private final ClassWriter cw;
	private final ClassVisitor cv;

	/**
	 * Construct a code generator for the given passage's target classfile
	 * 
	 * <p>
	 * This constructor chooses the name for the target classfile based on the passage's entry seed.
	 * It has the form: <code> Passage$at_<em>address</em>_<em>context</em></code>. The address is
	 * as rendered by {@link Address#toString()} but with characters replaced to make it a valid JVM
	 * classfile name. The decode context is rendered in hexadecimal. This constructor also declares
	 * the fields and methods, and emits the definition for {@link JitCompiledPassage#thread()}.
	 * 
	 * @param lookup a means of accessing user-defined components, namely userops
	 * @param context the analysis context for the passage
	 * @param cfm the control flow model
	 * @param dfm the data flow model
	 * @param vsm the variable scope model
	 * @param tm the type model
	 * @param am the allocation model
	 * @param oum the op use model
	 */
	public JitCodeGenerator(Lookup lookup, JitAnalysisContext context, JitControlFlowModel cfm,
			JitDataFlowModel dfm, JitVarScopeModel vsm, JitTypeModel tm, JitAllocationModel am,
			JitOpUseModel oum) {
		this.lookup = lookup;
		this.context = context;
		this.cfm = cfm;
		this.dfm = dfm;
		this.vsm = vsm;
		this.tm = tm;
		this.am = am;
		this.oum = oum;

		// TODO: Should I incorporate more of the address set into the name?
		AddrCtx entry = context.getPassage().getEntry();
		String pkgThis = lookup.lookupClass().getPackageName().replace(".", "/");
		if (!pkgThis.isEmpty()) {
			// Scripts are in the default package :/
			pkgThis = pkgThis + "/";
		}
		this.nameThis = (pkgThis + "Passage$at_" + entry.address + "_" + entry.biCtx.toString(16))
				.replace(":", "_")
				.replace(" ", "_");
		this.typeThis = Types.refExtends(JitCompiledPassage.class, "L" + nameThis + ";");

		int flags = entry.address.getOffset() == JitCompiler.EXCLUDE_MAXS ? 0
				: ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS;
		cw = new ClassWriter(flags);
		if (JitCompiler.ENABLE_DIAGNOSTICS.contains(Diag.TRACE_CLASS)) {
			cv = new TraceClassVisitor(cw, new PrintWriter(System.err));
		}
		else {
			this.cv = cw;
		}

		cv.visit(V17, ACC_PUBLIC, nameThis, null, Type.getInternalName(Object.class), new String[] {
			Type.getInternalName(JitCompiledPassage.class),
		});

		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, T_STRING, "LANGUAGE_ID",
			context.getLanguage().getLanguageID().toString());
		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, T_LANGUAGE, "LANGUAGE");
		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, T_ADDRESS_FACTORY, "ADDRESS_FACTORY");
		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, new TypeLiteral<List<AddrCtx>>() {},
			"ENTRIES");
		Fld.decl(cv, ACC_PRIVATE | ACC_FINAL, T_JIT_PCODE_THREAD, "thread");
		Fld.decl(cv, ACC_PRIVATE | ACC_FINAL, T_JIT_BYTES_PCODE_EXECUTOR_STATE, "state");

		var paramsThread = new Object() {
			Local<TRef<THIS>> this_;
		};
		var retThread = Emitter.start(typeThis, cv, ACC_PUBLIC, "thread",
			MthDesc.returns(T_JIT_PCODE_THREAD).build())
				.param(Def::done, typeThis, l -> paramsThread.this_ = l);
		retThread.em()
				.emit(Op::aload, paramsThread.this_)
				.emit(Op::getfield, typeThis, "thread", T_JIT_PCODE_THREAD)
				.emit(Op::areturn, retThread.ret())
				.emit(Misc::finish);
	}

	/**
	 * Get the analysis context
	 * 
	 * @return the context
	 */
	public JitAnalysisContext getAnalysisContext() {
		return context;
	}

	/**
	 * Get the variable scope model
	 * 
	 * @return the model
	 */
	public JitVarScopeModel getVariableScopeModel() {
		return vsm;
	}

	/**
	 * Get the type model
	 * 
	 * @return the model
	 */
	public JitTypeModel getTypeModel() {
		return tm;
	}

	/**
	 * Get the allocation model
	 * 
	 * @return the model
	 */
	public JitAllocationModel getAllocationModel() {
		return am;
	}

	/**
	 * Emit the first bytecodes for the static initializer
	 * 
	 * <p>
	 * This generates code equivalent to:
	 * 
	 * <pre>
	 * static {
	 * 	LANGUAGE = {@link JitCompiledPassage#getLanguage(String) getLanguage}(LANGUAGE_ID);
	 * 	ADDRESS_FACTORY = LANGUAGE.getAddressFactory();
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Note that {@code LANGUAGE_ID} is initialized to a constant {@link String} in its declaration.
	 * Additional {@link StaticFieldReq static fields} may be requested as the p-code translation is
	 * emitted.
	 */
	protected Emitter<Bot> startClInitMethod(Emitter<Bot> em) {
		return em
				.emit(Op::getstatic, typeThis, "LANGUAGE_ID", T_STRING)
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "getLanguage",
					MDESC_JIT_COMPILED_PASSAGE__GET_LANGUAGE, true)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::dup)
				.emit(Op::putstatic, typeThis, "LANGUAGE", T_LANGUAGE)
				.emit(Op::invokeinterface, T_LANGUAGE, "getAddressFactory",
					MDESC_LANGUAGE__GET_ADDRESS_FACTORY)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::putstatic, typeThis, "ADDRESS_FACTORY", T_ADDRESS_FACTORY);
	}

	/**
	 * Emit the first bytecodes for the class constructor
	 * 
	 * <p>
	 * This generates code equivalent to:
	 * 
	 * <pre>
	 * public Passage$at_00400000_0(JitPcodeThread thread) {
	 * 	super(); // Implicit in Java, but we must emit i
	 * 	this.thread = thread;
	 * 	this.state = thread.GetState();
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Additional {@link InstanceFieldReq instance fields} may be requested as the p-code
	 * translation is emitted.
	 */
	protected Emitter<Bot> startInitMethod(Emitter<Bot> em, Local<TRef<THIS>> localThis,
			Local<TRef<JitPcodeThread>> localThread) {
		return em
				// super();
				.emit(Op::aload, localThis)
				.emit(Op::invokespecial, T_OBJECT, "<init>", MDESC_OBJECT__$INIT, false)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				// this.thread = thread;
				.emit(Op::aload, localThis)
				.emit(Op::aload, localThread)
				.emit(Op::putfield, typeThis, "thread", T_JIT_PCODE_THREAD)
				// this.state = thread.getState();
				.emit(Op::aload, localThis)
				.emit(Op::aload, localThread)
				.emit(Op::invokevirtual, T_JIT_PCODE_THREAD, "getState",
					MDESC_JIT_PCODE_THREAD__GET_STATE, false)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::putfield, typeThis, "state", T_JIT_BYTES_PCODE_EXECUTOR_STATE);
	}

	/**
	 * Emit bytecode to load the given {@link JitBytesPcodeExecutorStateSpace} onto the JVM stack
	 * 
	 * <p>
	 * This is equivalent to the Java expression
	 * {@code state.getForSpace(AddressFactory.getAddressSpace(spaceId))}. The id of the given
	 * {@code space} is encoded as an immediate or in the constant pool and is represented as
	 * {@code spaceId}.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param space the space to load at run time
	 * @return the emitter with ..., stateSpace
	 */
	protected <N extends Next> Emitter<Ent<N, TRef<JitBytesPcodeExecutorStateSpace>>>
			genLoadJitStateSpace(Emitter<N> em, Local<TRef<THIS>> localThis, AddressSpace space) {
		return em
				/**
				 * return
				 * this.state.getForSpace(ADDRESS_FACTORY.getAddressSpace(`space.getSpaceID()`);
				 */
				.emit(Op::aload, localThis)
				.emit(Op::getfield, typeThis, "state", T_JIT_BYTES_PCODE_EXECUTOR_STATE)
				.emit(Op::getstatic, typeThis, "ADDRESS_FACTORY", T_ADDRESS_FACTORY)
				.emit(Op::ldc__i, space.getSpaceID())
				.emit(Op::invokeinterface, T_ADDRESS_FACTORY, "getAddressSpace",
					MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::invokeinterface, T_JIT_BYTES_PCODE_EXECUTOR_STATE, "getForSpace",
					MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_SPACE_FOR)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret);
	}

	/**
	 * Request a field for a {@link JitBytesPcodeExecutorStateSpace} for the given address space
	 * 
	 * @param space the address space
	 * @return the field request
	 */
	public FieldForSpaceIndirect requestFieldForSpaceIndirect(AddressSpace space) {
		return fieldsForSpaceIndirect.computeIfAbsent(space, s -> {
			FieldForSpaceIndirect f = new FieldForSpaceIndirect(s);
			return f;
		});
	}

	/**
	 * Request a field for the bytes backing the page at the given address
	 * 
	 * @param address the address contained by the desired page
	 * @return the field request
	 */
	public FieldForArrDirect requestFieldForArrDirect(Address address) {
		return fieldsForArrDirect.computeIfAbsent(address, a -> {
			FieldForArrDirect f = new FieldForArrDirect(a);
			return f;
		});
	}

	/**
	 * Request a field for the given contextreg value
	 * 
	 * @param ctx the contextreg value
	 * @return the field request
	 */
	protected FieldForContext requestStaticFieldForContext(RegisterValue ctx) {
		return fieldsForContext.computeIfAbsent(ctx, c -> {
			FieldForContext f = new FieldForContext(ctx);
			return f;
		});
	}

	/**
	 * Request a field for the given varnode
	 * 
	 * @param vn the varnode
	 * @return the field request
	 */
	public FieldForVarnode requestStaticFieldForVarnode(Varnode vn) {
		return fieldsForVarnode.computeIfAbsent(new VarnodeKey(vn), vk -> {
			FieldForVarnode f = new FieldForVarnode(vn);
			return f;
		});
	}

	/**
	 * Request a field for the given p-code op
	 * <p>
	 * This will request fields for each varnode for the op's operands
	 * 
	 * @param op the p-code op
	 * @return the field request
	 */
	public FieldForPcodeOp requestStaticFieldForOp(PcodeOp op) {
		return fieldsForOp.computeIfAbsent(new PcodeOpKey(op), ok -> new FieldForPcodeOp(this, op));
	}

	/**
	 * Request a field for the given userop
	 * 
	 * @param userop the userop
	 * @return the field request
	 */
	public FieldForUserop requestFieldForUserop(PcodeUseropDefinition<byte[]> userop) {
		return fieldsForUserop.computeIfAbsent(userop.getName(), n -> {
			FieldForUserop f = new FieldForUserop(userop);
			return f;
		});
	}

	/**
	 * Request a field for the {@link ExitSlot} for the given target
	 * 
	 * @param target the target address and decode context
	 * @return the field request
	 */
	public FieldForExitSlot requestFieldForExitSlot(AddrCtx target) {
		return fieldsForExitSlot.computeIfAbsent(target, t -> {
			FieldForExitSlot f = new FieldForExitSlot(t);
			return f;
		});
	}

	/**
	 * Get the label at the start of a block's translation
	 * 
	 * @param block the block
	 * @return the label
	 */
	public Lbl<Bot> labelForBlock(JitBlock block) {
		return blockLabels.computeIfAbsent(block, b -> Lbl.create());
	}

	/**
	 * Request an exception handler that can retire state for a given op
	 * 
	 * @param op the op that might throw an exception
	 * @param block the block containing the op
	 * @return the exception handler request
	 */
	public ExceptionHandler requestExceptionHandler(DecodedPcodeOp op, JitBlock block) {
		return excHandlers.computeIfAbsent(op, o -> new ExceptionHandler(o, block));
	}

	/**
	 * Emit into the constructor any bytecode necessary to support the given value.
	 * 
	 * @param v the value from the use-def graph
	 */
	protected <N extends Next> Emitter<N> genValInit(Emitter<N> em, Local<TRef<THIS>> localThis,
			JitVal v) {
		return ValGen.lookup(v).genValInit(em, localThis, this, v);
	}

	/**
	 * Emit bytecode to read the given value onto the JVM stack.
	 * 
	 * <p>
	 * Although the value may be assigned a type by the {@link JitTypeModel}, the type needed by a
	 * given op might be different.
	 * 
	 * @param <T> the required JVM type of the value
	 * @param <JT> the required p-code type of the value
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (source) value to read
	 * @param type the required p-code type of the value
	 * @param ext the kind of extension to apply
	 * @return the code visitor typed with the resulting stack, i.e., having pushed the value
	 */
	public <T extends BPrim<?>, JT extends SimpleJitType<T, JT>, N extends Next> Emitter<Ent<N, T>>
			genReadToStack(Emitter<N> em, Local<TRef<THIS>> localThis, JitVal v, JT type, Ext ext) {
		return ValGen.lookup(v).genReadToStack(em, localThis, this, v, type, ext);
	}

	/**
	 * Emit bytecode to read the given value into a series of locals
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (source) value to read
	 * @param type the required p-code type of the value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the operand containing the locals, and the emitter typed with the incoming stack
	 */
	public <N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitVal v, MpIntJitType type, Ext ext, Scope scope) {
		return ValGen.lookup(v).genReadToOpnd(em, localThis, this, v, type, ext, scope);
	}

	/**
	 * Emit bytecode to load one leg of a multi-precision value from the varnode onto the JVM stack.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (source) value to read
	 * @param type the p-code type of the complete multi-precision value
	 * @param leg the index of the leg to load, 0 being least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
	 */
	public <N extends Next> Emitter<Ent<N, TInt>> genReadLegToStack(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitVal v, MpIntJitType type, int leg, Ext ext) {
		return ValGen.lookup(v).genReadLegToStack(em, localThis, this, v, type, leg, ext);
	}

	/**
	 * Emit bytecode to load the varnode's value into an integer array in little-endian order,
	 * pushing its ref onto the JVM stack.
	 * <p>
	 * Ideally, multi-precision integers should be loaded into a series of locals, i.e., using
	 * {@link #genReadToOpnd(Emitter, Local, JitVal, MpIntJitType, Ext, Scope)}, but this may not
	 * always be the best course of action. The first case is for userops, where it'd be onerous and
	 * counter-intuitive for a user to receive a single varnode in several parameters. The
	 * annotation system to sort that all out would also be atrocious and not easily made compatible
	 * with non-JIT emulation. Instead, mp-int arguments are received via {@code int[]} parameters.
	 * 
	 * The second case is for more complicated p-code ops. One notable example is
	 * {@link IntMultOpGen int_mult}. Theoretically, yes, we could emit all of the operations to
	 * compute the product using long multiplication inline; however, for large operands, that would
	 * produce an enormous number of bytecodes. Given the 64KB-per-method limit, we could quickly
	 * squeeze ourselves out of efficient translation of lengthy passages. The {@code slack}
	 * parameter is provided since some of these algorithms (e.g., division) need an extra leg as
	 * scratch space. If we don't allocate it here, we force complexity into the implementation, as
	 * it would need to provide its own locals or re-allocate and copy the array.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (source) value to read
	 * @param type the p-code type of the complete multi-precision value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @param slack the number of additional, more significant, elements to allocate in the array
	 * @return the emitter typed with the resulting stack, i.e., having the ref pushed onto it
	 */
	public <N extends Next> Emitter<Ent<N, TRef<int[]>>> genReadToArray(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitVal v, MpIntJitType type, Ext ext, Scope scope,
			int slack) {
		return ValGen.lookup(v).genReadToArray(em, localThis, this, v, type, ext, scope, slack);
	}

	/**
	 * Emit bytecode to load the varnode's value, interpreted as a boolean, as an integer onto the
	 * JVM stack.
	 * <p>
	 * Any non-zero value is considered true, though ideally, slaspec authors should ensure all
	 * booleans are 1) 1-byte ints, and 2) only ever take the value 0 (false) or 1 (true).
	 * Nevertheless, we can't assume this guidance is followed. When we know a large (esp.
	 * multi-precision) variable is being used as a boolean, we have some opportunity for
	 * short-circuiting.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (source) value to read
	 * @return the emitter typed with the resulting stack, i.e., having the int boolean pushed onto
	 *         it
	 */
	public <N extends Next> Emitter<Ent<N, TInt>> genReadToBool(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitVal v) {
		return ValGen.lookup(v).genReadToBool(em, localThis, this, v);
	}

	/**
	 * Emit bytecode to write the value on the JVM stack into the given variable.
	 * 
	 * <p>
	 * Although the destination variable may be assigned a type by the {@link JitTypeModel}, the
	 * type of the value on the stack may not match. This method needs to know that type so that, if
	 * necessary, it can convert it to the appropriate JVM type for the local variable that holds
	 * it.
	 * 
	 * @param <T> the JVM type of the value on the stack
	 * @param <JT> the p-code type of the value on the stack
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (destination) variable to write
	 * @param type the p-code type of the value on the stack
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	public <T extends BPrim<?>, JT extends SimpleJitType<T, JT>, N1 extends Next,
		N0 extends Ent<N1, T>> Emitter<N1> genWriteFromStack(Emitter<N0> em,
				Local<TRef<THIS>> localThis, JitVar v, JT type, Ext ext, Scope scope) {
		return VarGen.lookup(v).genWriteFromStack(em, localThis, this, v, type, ext, scope);
	}

	/**
	 * Emit bytecode to store a varnode's value from several locals.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (destination) variable to write
	 * @param opnd the operand whose locals contain the value to be stored
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	public <N extends Next> Emitter<N> genWriteFromOpnd(Emitter<N> em, Local<TRef<THIS>> localThis,
			JitVar v, Opnd<MpIntJitType> opnd, Ext ext, Scope scope) {
		return VarGen.lookup(v).genWriteFromOpnd(em, localThis, this, v, opnd, ext, scope);
	}

	/**
	 * Emit bytecode to store a varnode's value from an array of integer legs, in little endian
	 * order
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the array ref on top
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param v the (destination) variable to write
	 * @param type the p-code type of the value on the stack
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the array
	 */
	public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1> genWriteFromArray(
			Emitter<N0> em, Local<TRef<THIS>> localThis, JitVar v, MpIntJitType type, Ext ext,
			Scope scope) {
		return VarGen.lookup(v).genWriteFromArray(em, localThis, this, v, type, ext, scope);
	}

	/**
	 * Emit the bytecode translation for a given p-code op
	 * 
	 * <p>
	 * This first finds the use-def node for the op and then verifies that it has not been
	 * eliminated. If not, then it find the appropriate generator, emits line number information,
	 * and then emits the actual translation.
	 * 
	 * <p>
	 * Line number information in the JVM is a map of strictly-positive line numbers to bytecode
	 * offsets. The ASM library allows this to be populated by placing labels and then emitting a
	 * line-number-to-label entry (via {@link MethodVisitor#visitLineNumber(int, Label)}. It seems
	 * the JVM presumes the entire class is defined in a single source file, so we are unable to
	 * (ab)use a filename field to encode debug information. We can encode the op index into the
	 * (integer) line number, although we have to add 1 to make it strictly positive.
	 * 
	 * @param em the emitter typed with the empty stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param localCtxmod a handle to the local holding {@code ctxmod}
	 * @param retReq an indication of what must be returned by this
	 *            {@link JitCompiledPassage#run(int)} method.
	 * @param op the op
	 * @param block the block containing the op
	 * @param opIdx the index of the op within the whole passage
	 */
	protected OpResult genOp(Emitter<Bot> em, Local<TRef<THIS>> localThis, Local<TInt> localCtxmod,
			RetReq<TRef<EntryPoint>> retReq, PcodeOp op, JitBlock block, int opIdx) {
		JitOp jitOp = dfm.getJitOp(op);
		if (!oum.isUsed(jitOp)) {
			return new LiveOpResult(em);
		}
		try (SubScope scope = em.rootScope().sub()) {
			return em
					.emit(Misc::lineNumber, opIdx)
					.emit(OpGen.lookup(jitOp)::genRun, localThis, localCtxmod, retReq, this, jitOp,
						block, scope);
		}
	}

	/**
	 * Emit the bytecode translation for the ops in the given p-code block
	 * 
	 * <p>
	 * This simply invokes {@link #genOp(Emitter, Local, Local, RetReq, PcodeOp, JitBlock, int)} on
	 * each op in the block and counts up the indices. Other per-block instrumentation is not
	 * included.
	 * 
	 * @param em the emitter
	 * @param localThis a handle to {@code this}
	 * @param localCtxmod a handle to {@code ctxmod}
	 * @param retReq the required return type, in case an op needs to exit the passage
	 * @param block the block
	 * @param opIdx the index, within the whole passage, of the first op in the block
	 * @return the result of block generation
	 * @see #genBlock(OpResult, Local, Local, RetReq, JitBlock, int)
	 */
	protected GenBlockResult genBlockOps(Emitter<Bot> em, Local<TRef<THIS>> localThis,
			Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq, JitBlock block, int opIdx) {
		OpResult result = new LiveOpResult(em);
		for (PcodeOp op : block.getCode()) {
			if (!(result instanceof LiveOpResult live)) {
				throw new AssertionError("Control flow died mid-block");
			}
			result = genOp(live.em(), localThis, localCtxmod, retReq, op, block, opIdx);
			opIdx++;
		}
		return new GenBlockResult(opIdx, result);
	}

	/**
	 * The result of generating code for a block of p-code ops
	 * 
	 * @param opIdx the index of the <em>next</em> op
	 * @param opResult the result of op generation, indicating whether or not control flow can fall
	 *            through
	 */
	record GenBlockResult(int opIdx, OpResult opResult) {}

	/**
	 * Emit the bytecode translation for the given p-code block
	 * 
	 * <p>
	 * This checks if the block needs a label, i.e., it is an entry or the target of a branch, and
	 * then optionally emits an invocation of {@link JitCompiledPassage#count(int, int)}. Finally,
	 * it emits the actual ops' translations via
	 * {@link #genBlockOps(Emitter, Local, Local, RetReq, JitBlock, int)}.
	 * 
	 * @param block the block
	 * @param opIdx the index, within the whole passage, of the first op in the block
	 * @return the index, within the whole passage, of the op immediately after the block
	 */
	protected GenBlockResult genBlock(OpResult prev, Local<TRef<THIS>> localThis,
			Local<TInt> localCtxmod, RetReq<TRef<EntryPoint>> retReq, JitBlock block, int opIdx) {
		LiveOpResult live;
		if (block.hasJumpTo() || getOpEntry(block.first()) != null) {
			live = new LiveOpResult(switch (prev) {
				case DeadOpResult r -> r.em().emit(Lbl::placeDead, labelForBlock(block));
				case LiveOpResult r -> r.em().emit(Lbl::place, labelForBlock(block));
			});
		}
		else if (prev instanceof LiveOpResult r) {
			live = r;
		}
		else {
			Msg.warn(this, "No control flow into block " + block.start());
			return new GenBlockResult(opIdx, prev);
			//throw new AssertionError("No control flow into a block");
		}

		Emitter<Bot> em;
		if (block.first() instanceof DecodedPcodeOp first &&
			context.getConfiguration().emitCounters()) {
			ExceptionHandler handler = requestExceptionHandler(first, block);

			var tryCatch = Misc.tryCatch(live.em(), Lbl.create(), handler.lbl(), T_THROWABLE);
			em = tryCatch.em()
					.emit(Op::aload, localThis)
					.emit(Op::ldc__i, block.instructionCount())
					.emit(Op::ldc__i, block.trailingOpCount())
					.emit(Op::invokeinterface, T_JIT_COMPILED_PASSAGE, "count",
						MDESC_JIT_COMPILED_PASSAGE__COUNT)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::takeObjRef)
					.step(Inv::retVoid)
					.emit(Lbl::place, tryCatch.end());
		}
		else {
			em = live.em();
		}
		return genBlockOps(em, localThis, localCtxmod, retReq, block, opIdx);
	}

	/**
	 * Emit code to load an {@link Address} onto the JVM stack
	 * 
	 * <p>
	 * Note this does not load the identical address, but reconstructs it at run time.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param address the address to load
	 * @return the emitter with ..., address
	 */
	protected <N extends Next> Emitter<Ent<N, TRef<Address>>> genAddress(Emitter<N> em,
			Address address) {
		if (address == Address.NO_ADDRESS) {
			return em
					.emit(Op::getstatic, T_ADDRESS, "NO_ADDRESS", T_ADDRESS);
		}
		return em
				.emit(Op::getstatic, typeThis, "ADDRESS_FACTORY", T_ADDRESS_FACTORY)
				.emit(Op::ldc__i, address.getAddressSpace().getSpaceID())
				.emit(Op::invokeinterface, T_ADDRESS_FACTORY, "getAddressSpace",
					MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::ldc__l, address.getOffset())
				.emit(Op::invokeinterface, T_ADDRESS_SPACE, "getAddress",
					MDESC_ADDRESS_SPACE__GET_ADDRESS)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret);
	}

	/**
	 * Emit bytecode into the class initializer that adds the given entry point into
	 * {@code ENTRIES}.
	 * 
	 * <p>
	 * Consider the entry {@code (ram:00400000,ctx=80000000)}. The code would be equivalent to:
	 * 
	 * <pre>
	 * static {
	 * 	ENTRIES.add(new AddrCtx(
	 * 		ADDRESS_FACTORY.getAddressSpace(ramId).getAddress(0x400000), CTX_80000000));
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Note this method will request the appropriate {@code CTX_...} field.
	 * 
	 * @param entry the entry point to add
	 */
	protected Emitter<Bot> genStaticEntry(Emitter<Bot> em, AddrCtx entry) {
		FieldForContext ctxField = requestStaticFieldForContext(entry.rvCtx);
		return em
				.emit(Op::getstatic, typeThis, "ENTRIES", T_LIST)
				.emit(Op::new_, T_ADDR_CTX)
				.emit(Op::dup)
				.emit(ctxField::genLoad, this)
				.emit(this::genAddress, entry.address)
				.emit(Op::invokespecial, T_ADDR_CTX, "<init>", MDESC_ADDR_CTX__$INIT, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::invokeinterface, T_LIST, "add", MDESC_LIST__ADD)
				.step(Inv::takeRefArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::pop);
	}

	/**
	 * Emit code into the static initializer to initialize the {@code ENTRIES} field.
	 * 
	 * <p>
	 * This first constructs a new {@link ArrayList} and assigns it to the field. Then, for each
	 * block representing a possible entry, it adds an element giving the address and contextreg
	 * value for the first op of that block.
	 */
	protected Emitter<Bot> genStaticEntries(Emitter<Bot> em) {
		em = em
				.emit(Op::new_, T_ARRAY_LIST)
				.emit(Op::dup)
				.emit(Op::invokespecial, T_ARRAY_LIST, "<init>", MDESC_ARRAY_LIST__$INIT, false)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::putstatic, typeThis, "ENTRIES", T_LIST);

		for (JitBlock block : cfm.getBlocks()) {
			AddrCtx entry = getOpEntry(block.first());
			if (entry != null) {
				em = genStaticEntry(em, entry);
			}
		}
		return em;
	}

	/**
	 * Emit bytecode for the static initializer
	 * <p>
	 * Note that this method must be called after the bytecode for the run method is generated,
	 * because that generator may request various static fields to be created and initialized. Those
	 * requests are not known until the run-method generator has finished.
	 * 
	 * @param em the emitter
	 * @return the emitter
	 */
	protected Emitter<Bot> genClInitMethod(Emitter<Bot> em) {
		for (FieldForContext fCtx : fieldsForContext.values()) {
			em = fCtx.genClInitCode(em, this, cv);
		}
		for (FieldForVarnode fVn : fieldsForVarnode.values()) {
			em = fVn.genClInitCode(em, this, cv);
		}
		for (FieldForPcodeOp fOp : fieldsForOp.values()) {
			em = fOp.genClInitCode(em, this, cv);
		}
		return em;
	}

	/**
	 * Emit all the bytecode for the constructor
	 * <p>
	 * Note that this must be called after the bytecode for the run method is generated, because
	 * that generator may request various instance fields to be created and initialized. Those
	 * requests are not known until the run-method generator has finished.
	 * <p>
	 * To ensure a reasonable order, for debugging's sake, we request fields (and their
	 * initializations) for all the variables and values before iterating over the ops. This
	 * ensures, e.g., locals are declared in order of address for the varnodes they hold. Similarly,
	 * the pre-fetched byte arrays, whether for uniques, registers, or memory are initialized in
	 * order of address. Were these requests not made, they'd still get requested by the op
	 * generators, but the order would be less helpful.
	 */
	protected Emitter<Bot> genInitMethod(Emitter<Bot> em, Local<TRef<THIS>> localThis) {
		// NOTE: Ops don't need init. They'll invoke field requests as needed.

		// Locals and values first, because they may request fields
		for (JvmLocal<?, ?> local : am.allLocals()) {
			em = local.genInit(em, this);
		}
		for (JitVal v : dfm.allValuesSorted()) {
			em = genValInit(em, localThis, v);
		}

		for (FieldForArrDirect fArr : fieldsForArrDirect.values()) {
			em = fArr.genInit(em, localThis, this, cv);
		}
		for (FieldForExitSlot fExit : fieldsForExitSlot.values()) {
			em = fExit.genInit(em, localThis, this, cv);
		}
		for (FieldForSpaceIndirect fSpace : fieldsForSpaceIndirect.values()) {
			em = fSpace.genInit(em, localThis, this, cv);
		}
		for (FieldForUserop fUserop : fieldsForUserop.values()) {
			em = fUserop.genInit(em, localThis, this, cv);
		}

		return em;
	}

	/**
	 * Emit all the bytecode for the {@link JitCompiledPassage#run(int) run} method.
	 * 
	 * <p>
	 * The structure of this method is described by this class's documentation. It first declares
	 * all the locals allocated by the {@link JitAllocationModel}. It then collects the list of
	 * entries points and assigns a label to each. These are used when emitting the entry dispatch
	 * code. Several of those labels may also be re-used when translating branch ops. We must
	 * iterate over the blocks in the same order as {@link #genStaticEntries(Emitter)}, so that our
	 * indices and its match. Thus, we emit a {@link Op#tableswitch(Emitter, int, Lbl, List)
	 * tableswitch} where each value maps to the blocks label identified in the same position of the
	 * {@code ENTRIES} field. We also provide a default case that just throws an
	 * {@link IllegalArgumentException}. We do not jump directly to the block's translation. Instead
	 * we emit a prologue for each block, wherein we birth the variables that block expects to be
	 * live, and then jump to the translation. Then, we emit the translation for each block using
	 * {@link #genBlock(OpResult, Local, Local, RetReq, JitBlock, int)}, placing transitions between
	 * those connected by fall through using
	 * {@link VarGen#computeBlockTransition(Local, JitCodeGenerator, JitBlock, JitBlock)}. Finally,
	 * we emit each requested exception handler using
	 * {@link ExceptionHandler#genRun(Emitter, Local, JitCodeGenerator)}.
	 */
	protected Emitter<Dead> genRunMethod(Emitter<Bot> em, Local<TRef<THIS>> localThis,
			Local<TInt> localBlockId, RetReq<TRef<EntryPoint>> retReq) {

		Local<TInt> localCtxmod = em.rootScope().decl(Types.T_INT, "ctxmod");
		em = em
				.emit(Op::ldc__i, 0)
				.emit(Op::istore, localCtxmod);

		am.allocate(em.rootScope());

		Map<JitBlock, Lbl<Bot>> entries = new LinkedHashMap<>();
		for (JitBlock block : cfm.getBlocks()) {
			AddrCtx entry = getOpEntry(block.first());
			if (entry != null) {
				entries.put(block, Lbl.create());
			}
		}
		Lbl<Bot> lblBadEntry = Lbl.create();

		var dead = em
				.emit(Op::iload, localBlockId)
				.emit(Op::tableswitch, 0, lblBadEntry, List.copyOf(entries.values()));

		for (Map.Entry<JitBlock, Lbl<Bot>> ent : entries.entrySet()) {
			JitBlock block = ent.getKey();
			dead = dead
					.emit(Lbl::placeDead, ent.getValue())
					.emit(VarGen.computeBlockTransition(localThis, this, null, block)::genFwd)
					.emit(Op::goto_, labelForBlock(block));
		}

		dead = dead
				.emit(Lbl::placeDead, lblBadEntry)
				.emit(Op::new_, T_ILLEGAL_ARGUMENT_EXCEPTION)
				.emit(Op::dup)
				.emit(Op::ldc__a, "Bad entry blockId")
				.emit(Op::invokespecial, T_ILLEGAL_ARGUMENT_EXCEPTION, "<init>",
					MDESC_ILLEGAL_ARGUMENT_EXCEPTION__$INIT, false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::athrow);

		/**
		 * NB. opIdx starts at 1, because JVM will ignore "Line number 0"
		 */
		int opIdx = 1;

		OpResult opResult = new DeadOpResult(dead);
		for (JitBlock block : cfm.getBlocks()) {
			var blockResult = genBlock(opResult, localThis, localCtxmod, retReq, block, opIdx);
			opIdx = blockResult.opIdx;
			JitBlock fall = block.getFallFrom();

			if (fall == null) {
				if (!(blockResult.opResult instanceof DeadOpResult r)) {
					throw new AssertionError("No fall-through, but control flow is live");
				}
				opResult = r;
			}
			else {
				opResult = switch (blockResult.opResult) {
					case LiveOpResult r -> new LiveOpResult(r.em()
							.emit(VarGen.computeBlockTransition(localThis, this, block,
								fall)::genFwd));
					case DeadOpResult r -> {
						/**
						 * This can happen, e.g., if an undefined userop is invoked. LATER: Perhaps
						 * have the control-flow analyzer consider this dead instead of
						 * fall-through?
						 */
						Msg.warn(this, "Fall-through block resulted in dead control flow.");
						yield r;
					}
				};
			}
		}
		if (!(opResult instanceof DeadOpResult r)) {
			throw new AssertionError("Final block left live control flow");
		}
		dead = r.em();

		for (ExceptionHandler handler : excHandlers.values()) {
			dead = dead
					.emit(handler::genRun, localThis, this);
		}
		return dead;
	}

	/**
	 * Generate the classfile for this passage and load it into this JVM.
	 * 
	 * @return the translation, wrapped in utilities that knows how to process and instantiate it
	 */
	public JitCompiledPassageClass load() {
		byte[] bytes = generate();
		return JitCompiledPassageClass.load(lookup, bytes);
	}

	/**
	 * For diagnostics: Dump the generated classfile to an actual file on disk
	 * 
	 * @param bytes the classfile bytes
	 * @return the same classfile bytes
	 * @see Diag#DUMP_CLASS
	 */
	protected byte[] dumpBytecode(byte[] bytes) {
		File dest = new File("build/gen/" + nameThis + ".class");
		dest.getParentFile().mkdirs();
		try (OutputStream os = new FileOutputStream(dest)) {
			os.write(bytes);
			new ProcessBuilder("javap", "-c", "-l", dest.getPath()).inheritIO().start().waitFor();
		}
		catch (IOException | InterruptedException e) {
			Msg.warn(this, "Could not dump class file: " + nameThis + " (" + e + ")");
		}
		return bytes;
	}

	/**
	 * Generate the classfile and get the raw bytes
	 * 
	 * <p>
	 * This emits all the bytecode for all the required methods, static initializer, and
	 * constructor. Once complete, this closes out the methods by letting the ASM library compute
	 * the JVM stack frames as well as the maximum stack size and local variable count. Finally, it
	 * closes out the class a retrieves the resulting bytes.
	 * 
	 * @return the classfile bytes
	 * @implNote The frame and maximums computation does not always succeed, and unfortunately, the
	 *           ASM library is not terribly keen to explain why. If {@link Diag#DUMP_CLASS} is
	 *           enabled, we will catch whatever hairy exception gets thrown and close out the
	 *           method anyway. The resulting class will not likely load into any JVM, but at least
	 *           you might be able to examine it.
	 */
	protected byte[] generate() {
		var paramsRun = new Object() {
			Local<TRef<THIS>> this_;
			Local<TInt> blockId;
		};
		var retRun = Emitter.start(typeThis, cv, ACC_PUBLIC, "run",
			MthDesc.returns(T_ENTRY_POINT).param(Types.T_INT).build())
				.param(Def::param, Types.T_INT, "blockId", l -> paramsRun.blockId = l)
				.param(Def::done, typeThis, l -> paramsRun.this_ = l);
		retRun.em()
				.emit(this::genRunMethod, paramsRun.this_, paramsRun.blockId, retRun.ret())
				.emit(Misc::finish);

		// Run may make requests of Init and ClInit
		var paramsInit = new Object() {
			Local<TRef<THIS>> this_;
			Local<TRef<JitPcodeThread>> thread;
		};
		var retInit = Emitter.start(typeThis, cv, ACC_PUBLIC, "<init>",
			MthDesc.returns(Types.T_VOID).param(T_JIT_PCODE_THREAD).build())
				.param(Def::param, T_JIT_PCODE_THREAD, "thread", l -> paramsInit.thread = l)
				.param(Def::done, typeThis, l -> paramsInit.this_ = l);
		retInit.em()
				.emit(this::startInitMethod, paramsInit.this_, paramsInit.thread)
				.emit(this::genInitMethod, paramsInit.this_)
				.emit(Op::return_, retInit.ret())
				.emit(Misc::finish);

		// Run and Init may make requests of ClInit
		var retClInit = Emitter.start(cv, ACC_PUBLIC, "<clinit>",
			MthDesc.returns(Types.T_VOID).build())
				.param(Def::done);
		retClInit.em()
				.emit(this::startClInitMethod)
				.emit(this::genClInitMethod)
				.emit(this::genStaticEntries)
				.emit(Op::return_, retClInit.ret())
				.emit(Misc::finish);

		cv.visitEnd();
		if (JitCompiler.ENABLE_DIAGNOSTICS.contains(Diag.DUMP_CLASS)) {
			return dumpBytecode(cw.toByteArray());
		}
		return cw.toByteArray();
	}

	/**
	 * Check if the given p-code op is the first of an instruction.
	 * 
	 * @param op the op to check
	 * @return the address-context pair
	 * @see JitPassage#getOpEntry(PcodeOp)
	 */
	public AddrCtx getOpEntry(PcodeOp op) {
		return context.getOpEntry(op);
	}

	/**
	 * Get the context of the instruction that generated the given p-code op.
	 * 
	 * <p>
	 * This is necessary when exiting the passage, whether due to an exception or "normal" exit. The
	 * emulator's context must be updated so that it can resume execution appropriately.
	 * 
	 * @param op the p-code op causing the exit
	 * @return the contextreg value
	 */
	public RegisterValue getExitContext(PcodeOp op) {
		if (op instanceof DecodedPcodeOp dec) {
			return dec.getContext();
		}
		throw new AssertionError("Couldn't figure exit context for " + op);
	}

	/**
	 * The manners in which the program counter and decode context can be "retired."
	 */
	public enum RetireMode {
		/**
		 * Retire into the emulator's counter/context and its machine state
		 * 
		 * @see JitCompiledPassage#writeCounterAndContext(long, RegisterValue)
		 */
		WRITE("writeCounterAndContext"),
		/**
		 * Retire into the emulator's counter/context, but not its machine state
		 * 
		 * @see JitCompiledPassage#setCounterAndContext(long, RegisterValue)
		 */
		SET("setCounterAndContext");

		private String mname;

		private RetireMode(String mname) {
			this.mname = mname;
		}
	}

	/**
	 * A mechanism to emit bytecode that loads a program counter
	 */
	public interface PcGen {
		/**
		 * Create a generator that loads a constant program counter value
		 * 
		 * @param address the program counter
		 * @return the generator
		 */
		public static PcGen loadOffset(Address address) {
			return new PcGen() {
				@Override
				public <N extends Next> Emitter<Ent<N, TLong>> gen(Emitter<N> em) {
					return em.emit(Op::ldc__l, address.getOffset());
				}
			};
		}

		/**
		 * Create a generator that loads a variable program counter
		 * 
		 * @param <THIS> the type of the generated passage
		 * @param localThis a handle to the local holding the {@code this} reference
		 * @param gen the code generator
		 * @param target the value (probably a variable) to load to get the program counter
		 * @return the generator
		 */
		public static <THIS extends JitCompiledPassage> PcGen loadTarget(
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitVal target) {
			return new PcGen() {
				@Override
				public <N extends Next> Emitter<Ent<N, TLong>> gen(Emitter<N> em) {
					return gen.genReadToStack(em, localThis, target, LongJitType.I8, Ext.ZERO);
				}
			};
		}

		/**
		 * Emit bytecode to load a program counter
		 * 
		 * @param <N> the incoming stack
		 * @param em the emitter typed with the incoming stack
		 * @return the emitter typed with the resulting stack, i.e., having pushed the counter value
		 */
		<N extends Next> Emitter<Ent<N, TLong>> gen(Emitter<N> em);
	}

	/**
	 * Emit bytecode to set the emulator's counter and contextreg.
	 * 
	 * <p>
	 * Within a translated passage, there's no need to keep constant track of the program counter
	 * (nor decode context), since all the decoding has already been done. However, whenever we exit
	 * the passage and return control back to the emulator (whether by {@code return} or
	 * {@code throw}) we must "retire" the program counter and decode context, as if the emulator
	 * had interpreted all the instructions just executed. This ensures that the emulator has the
	 * correct seed when seeking its next entry point, which may require decoding a new passage.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param pcGen a means to emit bytecode to load the counter (as a long) onto the JVM stack. For
	 *            errors, this is the address of the op causing the error. For branches, this is the
	 *            branch target, which may be loaded from a varnode for an indirect branch.
	 * @param ctx the contextreg value. For errors, this is the decode context of the op causing the
	 *            error. For branches, this is the decode context at the target.
	 * @param mode whether to set the machine state, too
	 * @return the emitter typed with the incoming stack
	 */
	public <N extends Next> Emitter<N> genRetirePcCtx(Emitter<N> em, Local<TRef<THIS>> localThis,
			PcGen pcGen, RegisterValue ctx, RetireMode mode) {
		return em
				.emit(Op::aload, localThis)
				.emit(pcGen::gen)
				.emit(c -> ctx == null
						? c.emit(Op::aconst_null, T_REGISTER_VALUE)
						: c.emit(requestStaticFieldForContext(ctx)::genLoad, this))
				.emit(Op::invokeinterface, T_JIT_COMPILED_PASSAGE, mode.mname,
					MDESC_JIT_COMPILED_PASSAGE__SET_$OR_WRITE_COUNTER_AND_CONTEXT)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid);
	}

	/**
	 * Emit code to exit the passage
	 * 
	 * <p>
	 * This retires all the variables of the current block as well as the program counter and decode
	 * context. It does not generate the actual {@link Opcodes#ARETURN areturn} or
	 * {@link Opcodes#ATHROW athrow}, but everything required up to that point.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param block the block containing the op at which we are exiting
	 * @param pcGen as in {@link #genRetirePcCtx(Emitter, Local, PcGen, RegisterValue, RetireMode)}
	 * @param ctx as in {@link #genRetirePcCtx(Emitter, Local, PcGen, RegisterValue, RetireMode)}
	 * @return the emitter with the incoming stack
	 */
	public <N extends Next> Emitter<N> genExit(Emitter<N> em, Local<TRef<THIS>> localThis,
			JitBlock block, PcGen pcGen, RegisterValue ctx) {
		return em
				.emit(VarGen.computeBlockTransition(localThis, this, block, null)::genFwd)
				.emit(this::genRetirePcCtx, localThis, pcGen, ctx, RetireMode.WRITE);
	}

	/**
	 * Get the error message for a given p-code op.
	 * 
	 * @param op the p-code op generating the error
	 * @return the message
	 * @see JitPassage#getErrorMessage(PcodeOp)
	 */
	public String getErrorMessage(PcodeOp op) {
		return context.getErrorMessage(op);
	}

	/**
	 * Get the address that generated the given p-code op.
	 * 
	 * <p>
	 * NOTE: The decoder rewrites ops to ensure they have the decode address, even if they were
	 * injected or from an inlined userop.
	 * 
	 * @param op the op
	 * @return the address, i.e., the program counter at the time the op is executed
	 */
	public Address getAddressForOp(PcodeOp op) {
		if (op instanceof DecodedPcodeOp dec) {
			return dec.getCounter();
		}
		return op.getSeqnum().getTarget();
	}

	/**
	 * For testing and debugging: A means to inject granular line number information
	 * 
	 * <p>
	 * Typically, this is used to assign every bytecode offset (emitted by a certain generator) a
	 * line number, so that tools expecting/requiring line numbers will display something useful.
	 */
	public static class LineNumberer {
		final MethodVisitor mv;
		int nextLine = 1;

		/**
		 * Prepare to number lines on the given method visitor
		 * 
		 * @param mv the method visitor
		 */
		public LineNumberer(MethodVisitor mv) {
			this.mv = mv;
		}

		/**
		 * Increment the line number and add info on the next bytecode index
		 */
		public void nextLine() {
			Label label = new Label();
			mv.visitLabel(label);
			mv.visitLineNumber(nextLine++, label);
		}
	}

	/**
	 * Resolve the type of the given value to the given behavior
	 * 
	 * @param val the value
	 * @param type the behavior
	 * @return the type
	 */
	public JitType resolveType(JitVal val, JitTypeBehavior type) {
		return type.resolve(tm.typeOf(val));
	}
}
