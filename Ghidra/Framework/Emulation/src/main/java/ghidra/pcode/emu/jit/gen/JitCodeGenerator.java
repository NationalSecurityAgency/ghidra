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

import org.objectweb.asm.*;
import org.objectweb.asm.util.TraceClassVisitor;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.JitPassage.DecodedPcodeOp;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmLocal;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.VarHandler;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.op.OpGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.ExitSlot;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass;
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
 * <li><b>{@code static }{@link List}{@code <}{@link AddrCtx}{@code > ENTRIES}</b> - The lsit of
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
 * <li>Parameter declarations - {@code this} and {@code blockId}</li>
 * <li>Allocated local declarations - declares all locals allocated by
 * {@link JitAllocationModel}</li>
 * <li>Entry point dispatch - a large {@code switch} statement on the entry {@code blockId}</li>
 * <li>P-code translation - the block-by-block op-by-op translation of the p-code to bytecode</li>
 * <li>Exception handlers - exception handlers as requested by various elements of the p-code
 * translation</li>
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
 */
public class JitCodeGenerator {
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
			this(vn.getSpace(), vn.getOffset(), vn.getSize());
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

	private final Map<JitBlock, Label> blockLabels = new HashMap<>();
	private final Map<PcodeOp, ExceptionHandler> excHandlers = new LinkedHashMap<>();
	private final Map<AddressSpace, FieldForSpaceIndirect> fieldsForSpaceIndirect = new HashMap<>();
	private final Map<Address, FieldForArrDirect> fieldsForArrDirect = new HashMap<>();
	private final Map<RegisterValue, FieldForContext> fieldsForContext = new HashMap<>();
	private final Map<VarnodeKey, FieldForVarnode> fieldsForVarnode = new HashMap<>();
	private final Map<String, FieldForUserop> fieldsForUserop = new HashMap<>();
	private final Map<AddrCtx, FieldForExitSlot> fieldsForExitSlot = new HashMap<>();

	final String nameThis;

	private final ClassWriter cw;
	private final ClassVisitor cv;
	private final MethodVisitor clinitMv;
	private final MethodVisitor initMv;
	private final MethodVisitor runMv;

	private final Label startLocals = new Label();
	private final Label endLocals = new Label();

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

		cv.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "LANGUAGE_ID", TDESC_STRING, null,
			context.getLanguage().getLanguageID().toString());
		cv.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "LANGUAGE", TDESC_LANGUAGE, null, null);
		cv.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "ADDRESS_FACTORY",
			TDESC_ADDRESS_FACTORY, null, null);
		cv.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "ENTRIES", TDESC_LIST,
			TSIG_LIST_ADDRCTX, null);

		cv.visitField(ACC_PRIVATE | ACC_FINAL, "thread", TDESC_JIT_PCODE_THREAD, null, null);
		cv.visitField(ACC_PRIVATE | ACC_FINAL, "state", TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE, null,
			null);

		clinitMv = cv.visitMethod(ACC_PUBLIC | ACC_STATIC, "<clinit>",
			Type.getMethodDescriptor(Type.VOID_TYPE), null, null);

		initMv = cv.visitMethod(ACC_PUBLIC, "<init>", Type.getMethodDescriptor(Type.VOID_TYPE,
			Type.getType(JitPcodeThread.class)), null, null);
		runMv = cv.visitMethod(ACC_PUBLIC, "run",
			Type.getMethodDescriptor(Type.getType(EntryPoint.class), Type.INT_TYPE), null, null);

		startStaticInitializer();
		startConstructor();

		MethodVisitor gtMv = cw.visitMethod(ACC_PUBLIC, "thread",
			Type.getMethodDescriptor(Type.getType(JitPcodeThread.class)), null, null);
		gtMv.visitCode();
		// []
		gtMv.visitVarInsn(ALOAD, 0);
		// [this]
		gtMv.visitFieldInsn(GETFIELD, nameThis, "thread", TDESC_JIT_PCODE_THREAD);
		// [thread]
		gtMv.visitInsn(ARETURN);
		// []
		gtMv.visitMaxs(20, 20);
		gtMv.visitEnd();
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
	protected void startStaticInitializer() {
		clinitMv.visitCode();

		// []
		clinitMv.visitFieldInsn(GETSTATIC, nameThis, "LANGUAGE_ID", TDESC_STRING);
		// [langID:STR]
		clinitMv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "getLanguage",
			MDESC_JIT_COMPILED_PASSAGE__GET_LANGUAGE, true);
		// [language]
		clinitMv.visitInsn(DUP);
		// [language,language]
		clinitMv.visitFieldInsn(PUTSTATIC, nameThis, "LANGUAGE", TDESC_LANGUAGE);
		// [language]
		clinitMv.visitMethodInsn(INVOKEINTERFACE, NAME_LANGUAGE, "getAddressFactory",
			MDESC_LANGUAGE__GET_ADDRESS_FACTORY, true);
		clinitMv.visitFieldInsn(PUTSTATIC, nameThis, "ADDRESS_FACTORY", TDESC_ADDRESS_FACTORY);
		// []
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
	protected void startConstructor() {
		initMv.visitCode();
		// Object.super()
		// []
		initMv.visitVarInsn(ALOAD, 0);
		// [this]
		initMv.visitMethodInsn(INVOKESPECIAL, NAME_OBJECT, "<init>",
			Type.getMethodDescriptor(Type.VOID_TYPE), false);
		// []

		// this.thread = thread
		// []
		initMv.visitVarInsn(ALOAD, 0);
		// [this]
		initMv.visitVarInsn(ALOAD, 1);
		// [this,state]
		initMv.visitFieldInsn(PUTFIELD, nameThis, "thread", TDESC_JIT_PCODE_THREAD);
		// []

		// this.state = thread.getState()
		// []
		initMv.visitVarInsn(ALOAD, 0);
		// [this]
		initMv.visitVarInsn(ALOAD, 1);
		// [this,thread]
		initMv.visitMethodInsn(INVOKEVIRTUAL, NAME_JIT_PCODE_THREAD, "getState",
			MDESC_JIT_PCODE_THREAD__GET_STATE, false);
		// [this,state]
		initMv.visitFieldInsn(PUTFIELD, nameThis, "state", TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE);
		// []
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
	 * @param space the space to load at run time
	 * @param iv the visitor for the class constructor
	 */
	protected void generateLoadJitStateSpace(AddressSpace space, MethodVisitor iv) {
		/**
		 * this.spaceInd_`space` =
		 * this.state.getForSpace(ADDRESS_FACTORY.getAddressSpace(`space.getSpaceID()`);
		 */

		iv.visitVarInsn(ALOAD, 0);
		// [...,this]
		iv.visitFieldInsn(GETFIELD, nameThis, "state",
			TDESC_JIT_BYTES_PCODE_EXECUTOR_STATE);
		// [...,state]
		iv.visitFieldInsn(GETSTATIC, nameThis, "ADDRESS_FACTORY", TDESC_ADDRESS_FACTORY);
		// [...,state,factory]
		iv.visitLdcInsn(space.getSpaceID());
		// [...,state,factory,spaceid]
		iv.visitMethodInsn(INVOKEINTERFACE, NAME_ADDRESS_FACTORY, "getAddressSpace",
			MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE, true);
		// [...,state,space]
		iv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_BYTES_PCODE_EXECUTOR_STATE, "getForSpace",
			MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE__GET_SPACE_FOR, true);
		// [...,jitspace]
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
			f.generateInitCode(this, cv, initMv);
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
			f.generateInitCode(this, cv, initMv);
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
			f.generateClinitCode(this, cv, clinitMv);
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
			f.generateClinitCode(this, cv, clinitMv);
			return f;
		});
	}

	/**
	 * Request a field for the given userop
	 * 
	 * @param userop the userop
	 * @return the field request
	 */
	public FieldForUserop requestFieldForUserop(PcodeUseropDefinition<?> userop) {
		return fieldsForUserop.computeIfAbsent(userop.getName(), n -> {
			FieldForUserop f = new FieldForUserop(userop);
			f.generateInitCode(this, cv, initMv);
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
			f.generateInitCode(this, cv, initMv);
			return f;
		});
	}

	/**
	 * Get the label at the start of a block's translation
	 * 
	 * @param block the block
	 * @return the label
	 */
	public Label labelForBlock(JitBlock block) {
		return blockLabels.computeIfAbsent(block, b -> new Label());
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
	protected void generateValInitCode(JitVal v) {
		ValGen.lookup(v).generateValInitCode(this, v, initMv);
	}

	/**
	 * Emit into the {@link JitCompiledPassage#run(int) run} method the bytecode to read the given
	 * value onto the JVM stack.
	 * 
	 * <p>
	 * Although the value may be assigned a type by the {@link JitTypeModel}, the type needed by a
	 * given op might be different. This method accepts the {@link JitTypeBehavior} for the operand
	 * and will ensure the value pushed onto the JVM stack is compatible with that type.
	 * 
	 * @param v the value to read
	 * @param typeReq the required type of the value
	 * @return the actual type of the value on the stack
	 */
	public JitType generateValReadCode(JitVal v, JitTypeBehavior typeReq) {
		return ValGen.lookup(v).generateValReadCode(this, v, typeReq, runMv);
	}

	/**
	 * Emit into the {@link JitCompiledPassage#run(int) run} method the bytecode to write the value
	 * on the JVM stack into the given variable.
	 * 
	 * <p>
	 * Although the destination variable may be assigned a type by the {@link JitTypeModel}, the
	 * type of the value on the stack may not match. This method needs to know that type so that, if
	 * necessary, it can convert it to the appropriate JVM type for local variable that holds it.
	 * 
	 * @param v the variable to write
	 * @param type the actual type of the value on the stack
	 */
	public void generateVarWriteCode(JitVar v, JitType type) {
		VarGen.lookup(v).generateVarWriteCode(this, v, type, runMv);
	}

	/**
	 * Emit all the bytecode for the constructor
	 * 
	 * <p>
	 * Note that some elements of the p-code translation may request additional bytecodes to be
	 * emitted, even after this method is finished. That code will be emitted at the time requested.
	 * 
	 * <p>
	 * To ensure a reasonable order, for debugging's sake, we request fields (and their
	 * initializations) for all the variables and values before iterating over the ops. This
	 * ensures, e.g., locals are declared in order of address for the varnodes they hold. Similarly,
	 * the pre-fetched byte arrays, whether for uniques, registers, or memory are initialized in
	 * order of address. Were these requests not made, they'd still get requested by the op
	 * generators, but the order would be less helpful.
	 */
	protected void generateInitCode() {
		for (JvmLocal local : am.allLocals()) {
			local.generateInitCode(this, initMv);
		}
		for (JitVal v : dfm.allValuesSorted()) {
			generateValInitCode(v);
		}
		for (PcodeOp op : context.getPassage().getCode()) {
			JitOp jitOp = dfm.getJitOp(op);
			if (!oum.isUsed(jitOp)) {
				continue;
			}
			OpGen.lookup(jitOp).generateInitCode(this, jitOp, initMv);
		}
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
	 * @param op the op
	 * @param block the block containing the op
	 * @param opIdx the index of the op within the whole passage
	 */
	protected void generateCodeForOp(PcodeOp op, JitBlock block, int opIdx) {
		JitOp jitOp = dfm.getJitOp(op);
		if (!oum.isUsed(jitOp)) {
			return;
		}
		Label lblLine = new Label();
		runMv.visitLabel(lblLine);
		runMv.visitLineNumber(opIdx, lblLine);
		OpGen.lookup(jitOp).generateRunCode(this, jitOp, block, runMv);
	}

	/**
	 * Emit the bytecode translation for the ops in the given p-code block
	 * 
	 * <p>
	 * This simply invoked {@link #generateCodeForOp(PcodeOp, JitBlock, int)} on each op in the
	 * block and counts up the indices. Other per-block instrumentation is not included.
	 * 
	 * @param block the block
	 * @param opIdx the index, within the whole passage, of the first op in the block
	 * @return the index, within the whole passage, of the op immediately after the block
	 * @see #generateCodeForBlock(JitBlock, int)
	 */
	protected int generateCodeForBlockOps(JitBlock block, int opIdx) {
		for (PcodeOp op : block.getCode()) {
			generateCodeForOp(op, block, opIdx);
			opIdx++;
		}
		return opIdx;
	}

	/**
	 * Emit the bytecode translation for the given p-code block
	 * 
	 * <p>
	 * This checks if the block needs a label, i.e., it is an entry or the target of a branch, and
	 * then optionally emits an invocation of {@link JitCompiledPassage#count(int, int)}. Finally,
	 * it emits the actual ops' translations via {@link #generateCodeForBlockOps(JitBlock, int)}.
	 * 
	 * @param block the block
	 * @param opIdx the index, within the whole passage, of the first op in the block
	 * @return the index, within the whole passage, of the op immediately after the block
	 */
	protected int generateCodeForBlock(JitBlock block, int opIdx) {
		if (block.hasJumpTo() || getOpEntry(block.first()) != null) {
			Label start = labelForBlock(block);
			runMv.visitLabel(start);
		}

		if (block.first() instanceof DecodedPcodeOp first &&
			context.getConfiguration().emitCounters()) {
			final Label tryStart = new Label();
			final Label tryEnd = new Label();
			runMv.visitTryCatchBlock(tryStart, tryEnd,
				requestExceptionHandler(first, block).label(), NAME_THROWABLE);

			runMv.visitLabel(tryStart);
			runMv.visitVarInsn(ALOAD, 0);
			runMv.visitLdcInsn(block.instructionCount());
			runMv.visitLdcInsn(block.trailingOpCount());
			runMv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_COMPILED_PASSAGE, "count",
				MDESC_JIT_COMPILED_PASSAGE__COUNT, true);
			runMv.visitLabel(tryEnd);
		}

		return generateCodeForBlockOps(block, opIdx);
	}

	/**
	 * Emit code to load an {@link Address} onto the JVM stack
	 * 
	 * <p>
	 * Note this does not load the identical address, but reconstructs it at run time.
	 * 
	 * @param address the address to load
	 * @param mv the visitor for the method being generated
	 */
	protected void generateAddress(Address address, MethodVisitor mv) {
		if (address == Address.NO_ADDRESS) {
			mv.visitFieldInsn(GETSTATIC, NAME_ADDRESS, "NO_ADDRESS", TDESC_ADDRESS);
			return;
		}

		// []
		mv.visitFieldInsn(GETSTATIC, nameThis, "ADDRESS_FACTORY", TDESC_ADDRESS_FACTORY);
		// [factory]
		mv.visitLdcInsn(address.getAddressSpace().getSpaceID());
		// [factory,spaceid]
		mv.visitMethodInsn(INVOKEINTERFACE, NAME_ADDRESS_FACTORY, "getAddressSpace",
			MDESC_ADDRESS_FACTORY__GET_ADDRESS_SPACE, true);
		// [space]
		mv.visitLdcInsn(address.getOffset());
		// [space,offset]
		mv.visitMethodInsn(INVOKEINTERFACE, NAME_ADDRESS_SPACE, "getAddress",
			MDESC_ADDRESS_SPACE__GET_ADDRESS, true);
		// [addr]
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
	protected void generateStaticEntry(AddrCtx entry) {
		FieldForContext ctxField = requestStaticFieldForContext(entry.rvCtx);

		// []
		clinitMv.visitFieldInsn(GETSTATIC, nameThis, "ENTRIES", TDESC_LIST);
		// [entries]
		clinitMv.visitTypeInsn(NEW, NAME_ADDR_CTX);
		// [entries,addrCtx:NEW]
		clinitMv.visitInsn(DUP);
		// [entries,addrCtx:NEW,addrCtx:NEW]
		ctxField.generateLoadCode(this, clinitMv);
		// [entries,addrCtx:NEW,addrCtx:NEW,ctx]
		generateAddress(entry.address, clinitMv);
		// [entries,addrCtx:NEW,addrCtx:NEW,ctx,addr]
		clinitMv.visitMethodInsn(INVOKESPECIAL, NAME_ADDR_CTX, "<init>", MDESC_ADDR_CTX__$INIT,
			false);
		// [entries,addrCtx:NEW]
		clinitMv.visitMethodInsn(INVOKEINTERFACE, NAME_LIST, "add", MDESC_LIST__ADD, true);
		// [result:BOOL]
		clinitMv.visitInsn(POP);
		// []
	}

	/**
	 * Emit code into the static initializer to initialize the {@code ENTRIES} field.
	 * 
	 * <p>
	 * This first constructs a new {@link ArrayList} and assigns it to the field. Then, for each
	 * block representing a possible entry, it adds an element giving the address and contextreg
	 * value for the first op of that block.
	 */
	protected void generateStaticEntries() {
		// []
		clinitMv.visitTypeInsn(NEW, NAME_ARRAY_LIST);
		// [entries:NEW]
		clinitMv.visitInsn(DUP);
		// [entries:NEW,entries:NEW]
		clinitMv.visitMethodInsn(INVOKESPECIAL, NAME_ARRAY_LIST, "<init>", MDESC_ARRAY_LIST__$INIT,
			false);
		// [entries:NEW]
		clinitMv.visitFieldInsn(PUTSTATIC, nameThis, "ENTRIES", TDESC_LIST);
		// []

		for (JitBlock block : cfm.getBlocks()) {
			AddrCtx entry = getOpEntry(block.first());
			if (entry != null) {
				generateStaticEntry(entry);
			}
		}
	}

	/**
	 * Emit all the bytecode for the {@link JitCompiledPassage#run(int) run} method.
	 * 
	 * <p>
	 * The structure of this method is described by this class's documentation. It first declares
	 * all the locals allocated by the {@link JitAllocationModel}. It then collects the list of
	 * entries points and assigns a label to each. These are used when emitting the entry dispatch
	 * code. Several of those labels may also be re-used when translating branch ops. We must
	 * iterate over the blocks in the same order as {@link #generateStaticEntries()}, so that our
	 * indices and its match. Thus, we emit a {@link Opcodes#TABLESWITCH tableswitch} where each
	 * value maps to the blocks label identified in the same position of the {@code ENTRIES} field.
	 * We also provide a default case that just throws an {@link IllegalArgumentException}. We do
	 * not jump directly to the block's translation. Instead we emit a prologue for each block,
	 * wherein we birth the variables that block expects to be live, and then jump to the
	 * translation. Then, we emit the translation for each block using
	 * {@link #generateCodeForBlock(JitBlock, int)}, placing transitions between those connected by
	 * fall through using
	 * {@link VarGen#computeBlockTransition(JitCodeGenerator, JitBlock, JitBlock)}. Finally, we emit
	 * each requested exception handler using
	 * {@link ExceptionHandler#generateRunCode(JitCodeGenerator, MethodVisitor)}.
	 */
	protected void generateRunCode() {
		runMv.visitCode();
		runMv.visitLabel(startLocals);

		runMv.visitLocalVariable("this", "L" + nameThis + ";", null, startLocals, endLocals, 0);
		runMv.visitLocalVariable("blockId", Type.getDescriptor(int.class), null, startLocals,
			endLocals, 1);

		for (JvmLocal local : am.allLocals()) {
			local.generateDeclCode(this, startLocals, endLocals, runMv);
		}
		// TODO: This for loop doesn't actually do anything....
		for (JitVal v : dfm.allValuesSorted()) {
			VarHandler handler = am.getHandler(v);
			handler.generateDeclCode(this, startLocals, endLocals, runMv);
		}
		/**
		 * NB. opIdx starts at 1, because JVM will ignore "Line number 0"
		 */
		int opIdx = 1;

		List<Label> entries = new ArrayList<>();
		for (JitBlock block : cfm.getBlocks()) {
			AddrCtx entry = getOpEntry(block.first());
			if (entry != null) {
				Label lblEntry = new Label();
				entries.add(lblEntry);
			}
		}

		// []
		runMv.visitVarInsn(ILOAD, 1);
		// [blockId]
		Label lblBadEntry = new Label();
		runMv.visitTableSwitchInsn(0, entries.size() - 1, lblBadEntry,
			entries.toArray(Label[]::new));
		// []

		Iterator<Label> eit = entries.iterator();
		for (JitBlock block : cfm.getBlocks()) {
			AddrCtx entry = getOpEntry(block.first());
			if (entry != null) {
				Label lblEntry = eit.next();
				runMv.visitLabel(lblEntry);
				VarGen.computeBlockTransition(this, null, block).generate(runMv);
				runMv.visitJumpInsn(GOTO, labelForBlock(block));
			}
		}
		runMv.visitLabel(lblBadEntry);
		// []
		runMv.visitTypeInsn(NEW, NAME_ILLEGAL_ARGUMENT_EXCEPTION);
		// [err:NEW]
		runMv.visitInsn(DUP);
		// [err:NEW,err:NEW]
		runMv.visitLdcInsn("Bad entry blockId");
		// [err:NEW,err:NEW,message]
		runMv.visitMethodInsn(INVOKESPECIAL, NAME_ILLEGAL_ARGUMENT_EXCEPTION, "<init>",
			MDESC_ILLEGAL_ARGUMENT_EXCEPTION__$INIT, false);
		// [err]
		runMv.visitInsn(ATHROW);
		// []

		for (JitBlock block : cfm.getBlocks()) {
			opIdx = generateCodeForBlock(block, opIdx);
			JitBlock fall = block.getFallFrom();
			if (fall != null) {
				VarGen.computeBlockTransition(this, block, fall).generate(runMv);
			}
		}

		for (ExceptionHandler handler : excHandlers.values()) {
			handler.generateRunCode(this, runMv);
		}
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
		}
		catch (IOException e) {
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
		generateStaticEntries();
		generateInitCode();
		generateRunCode();

		clinitMv.visitInsn(RETURN);
		clinitMv.visitMaxs(20, 20);
		clinitMv.visitEnd();

		initMv.visitInsn(RETURN);
		initMv.visitMaxs(20, 20);
		initMv.visitEnd();

		runMv.visitLabel(endLocals);
		try {
			runMv.visitMaxs(20, 20);
		}
		catch (Exception e) {
			if (JitCompiler.ENABLE_DIAGNOSTICS.contains(Diag.DUMP_CLASS)) {
				// At least try to get bytecode out for diagnostics
				runMv.visitEnd();
				cv.visitEnd();
				dumpBytecode(cw.toByteArray());
			}
			throw e;
		}
		runMv.visitEnd();

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
	 * @param pcGen a means to emit bytecode to load the counter (as a long) onto the JVM stack. For
	 *            errors, this is the address of the op causing the error. For branches, this is the
	 *            branch target, which may be loaded from a varnode for an indirect branch.
	 * @param ctx the contextreg value. For errors, this is the decode context of the op causing the
	 *            error. For branches, this is the decode context at the target.
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	public void generateRetirePcCtx(Runnable pcGen, RegisterValue ctx,
			MethodVisitor rv) {
		// []
		rv.visitVarInsn(ALOAD, 0);
		// [this]
		pcGen.run();
		// [this,pc:LONG]
		if (ctx == null) { // TODO: Or if it's same as entry?
			rv.visitInsn(ACONST_NULL);
		}
		else {
			requestStaticFieldForContext(ctx).generateLoadCode(this, rv);
		}
		// [this,pc:LONG,ctx:RV]
		rv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_COMPILED_PASSAGE, "retireCounterAndContext",
			MDESC_JIT_COMPILED_PASSAGE__RETIRE_COUNTER_AND_CONTEXT, true);
	}

	/**
	 * Emit code to exit the passage
	 * 
	 * <p>
	 * This retires all the variables of the current block as well as the program counter and decode
	 * coontext. It does not generate the actual {@link Opcodes#ARETURN areturn} or
	 * {@link Opcodes#ATHROW athrow}, but everything required up to that point.
	 * 
	 * @param block the block containing the op at which we are exiting
	 * @param pcGen as in {@link #generateRetirePcCtx(Runnable, RegisterValue, MethodVisitor)}
	 * @param ctx as in {@link #generateRetirePcCtx(Runnable, RegisterValue, MethodVisitor)}
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	public void generatePassageExit(JitBlock block, Runnable pcGen, RegisterValue ctx,
			MethodVisitor rv) {
		VarGen.computeBlockTransition(this, block, null).generate(rv);
		generateRetirePcCtx(pcGen, ctx, rv);
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
}
