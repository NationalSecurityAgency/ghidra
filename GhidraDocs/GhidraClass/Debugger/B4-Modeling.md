
# P-code Modeling

This module assumes you have completed the [Emulation](B2-Emulation.md) and [Scripting](B3-Scripting.md) portions of this course.
It also assumes you have fairly deep knowledge of Ghidra's low p-code.

Modeling is another one of those loaded terms.
Here we are going to focus on its use in what we will call *augmented emulation*.
This is used for things like dynamic taint analysis and concolic execution.
The idea is to leverage the emulator for concrete execution while augmenting it with some auxiliary model, e.g., taint labels or symbolic expressions.
Ghidra's abstract emulator implementations facilitate the composition of independent models so, if careful attention is given to your implementation, the auxiliary model can be re-used for other cases, perhaps even in static analysis.

This module will address the following aspects of modeling:

* Environment, i.e., p-code userops and stubbing.
* Arithmetic operations.
* Storage, addressing, and memory operations.
* Use in dynamic analysis.
* Use in static analysis.
* Integration with the GUI.

Modeling is definitely a development task.
There is generally a specific interface for each aspect, and Ghidra may provide abstract implementations of them, which you may choose to use or ignore.
If you do not already have a development environment set up, you will need to do that now.
Either use the GhidraDev plugin for Eclipse and associate it with an installation of Ghidra, or clone the `ghidra` source repository and prepare it for development in Eclipse.
When prototyping, you may find it easiest to develop a script, which is what this tutorial will do.

## Modeling the Environment

There are different pieces to the environment.
This covers the implementation of p-code userops, which generally covers everything not modeled by p-code.
For example, the x86-64 `SYSCALL` instruction just invokes the `syscall()` userop, which provides a hook for implementing them.
Modeling system calls is such a common case that Ghidra provides a special programming interface for it.
Stubbing external functions is covered, in part, by the [Emulation](B2-Emulation.md) module.
By providing common stubs in a userop library, the user can stub the external function by placing a Sleigh breakpoint that invokes the appropriate userop.

### Modeling by Java Callbacks

A userop library is created by implementing the `PcodeUseropLibrary` interface, most likely by extending `AnnotatedPcodeUseropLibrary`.
For example, to provide a stub for `strlen`:

```java {.numberLines}
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
```

Here, we implement the stub using Java callbacks.
This is more useful when modeling things outside of Ghidra's definition of machine state, e.g., to simulate kernel objects in an underlying operating system.
Nevertheless, it can be used to model simple state changes as well.
A user would place a breakpoint at either the call site or the call target, have it invoke `__libc_strlen()`, and then invoke either `emu_skip_decoded()` or `__x86_64_RET()` depending on where the breakpoint was placed.

### Modeling by Sleigh Semantics

The advantage to Java callbacks is that things are relatively intuitive to do, but the temptation, which we intentionally demonstrate here, is to make everything concrete.
You may notice the library uses a type parameter `T`, which specifies the type of all variables in the emulator's state.
Leaving it as `T` indicates the library is compatible with any type.
For a concrete emulator, `T = byte[]`, and so there is no loss in making things concrete, and then converting back to `T` using the arithmetic object.
However, if the emulator has been augmented, as we will discuss below, the model may become confused, because values computed by a careless userop will appear to the model a literal constant.
To avoid this, you should keep everything a T and use the arithmetic object to perform any arithmetic operations.
Alternatively, you can implement the userop using pre-compiled Sleigh code:

```java {.numberLines}
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
```

At construction, we capture the varnodes we need to use.
We could just use them directly in the source, but this demonstrates the ability to alias them, which makes the Sleigh source more re-usable across target architectures.
We then lazily compile each userop upon its first invocation.
These are technically still Java callbacks, but our implementation delegates to the executor, giving it the compiled p-code program.

The advantage here is that the code will properly use the underlying arithmetic appropriately.
However, for some models, that may actually not be desired.
Some symbolic models might just like to see a literal call to `strlen()`.

### Modeling by Structured Sleigh

The disadvantage to pre-compiled p-code is all the boilerplate and manual handling of Sleigh compilation.
Additionally, when stubbing C functions, you have to be mindful of the types, and things may get complicated enough that you pine for more C-like control structures.
The same library can be implemented using an incubating feature we call *Structured Sleigh*:

```java {.numberLines}
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
```

This is about as succinct as we can get specifying p-code behaviors in Java.
While these may appear like callbacks into Java methods that use a special API for state manipulation, that is not entirely accurate.
The Java method is invoked once as a way to "transpile" the Structured Sleigh into standard Sleigh semantic code.
That code is then compiled to p-code, which will be executed whenever the userop is called.
In a sense, Structured Sleigh is a DSL hosted in Java....

Unfortunately, we cannot overload operators in Java, so we are stuck using method invocations.
Another disadvantage is the dependence on a compiler spec for type resolution.
Structured Sleigh is not the best suited for all circumstances, e.g., the implementation of `__x86_64_RET` is odd to express.
Arguably, there is no real need to ascribe high-level types to `RSP` and `RIP` when expressing low-level operations.
Luckily, these implementation techniques can be mixed.
A single library can implement the `RET` using pre-compiled Sleigh, but `strlen` using Structured Sleigh.

### Modeling System Calls

We will not cover this in depth, but here are some good examples:

* [DemoSyscallLibrary](../../../Ghidra/Features/SystemEmulation/ghidra_scripts/DemoSyscallLibrary.java)
* [EmuLinuxAmd64SyscallUseropLibrary](../../../Ghidra/Features/SystemEmulation/src/main/java/ghidra/pcode/emu/linux/EmuLinuxAmd64SyscallUseropLibrary.java)
* [EmuLinuxX86SyscallUseropLibrary](../../../Ghidra/Features/SystemEmulation/src/main/java/ghidra/pcode/emu/linux/EmuLinuxX86SyscallUseropLibrary.java)

More can be obtained by finding all implementations of `EmuSyscallLibrary` in your IDE.
The Linux system call libraries are incomplete.
They only provide a few simple file operations, but it is sufficient to demonstrate the simulation of an underlying operating system.
They can also be extended and/or composed to provide additional system calls.

### Using Custom Userop Libraries

The use of a custom library in a stand-alone emulation script is pretty straightforward:

```java {.numberLines}
public class CustomLibraryScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		PcodeEmulator emu = new PcodeEmulator(currentProgram.getLanguage()) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return super.createUseropLibrary()
						.compose(new ModelingScript.StructuredStdLibPcodeUseropLibrary<>(
							currentProgram.getCompilerSpec()));
			}
		};
		emu.inject(currentAddress, """
				__libc_strlen();
				__X86_64_RET();
				""");
		// TODO: Initialize the emulator's memory from the current program
		PcodeThread<byte[]> thread = emu.newThread();
		// TODO: Initialize the thread's registers

		while (true) {
			monitor.checkCancelled();
			thread.stepInstruction(100);
		}
	}
}
```

The key is to override `createUseropLibrary()` in an anonymous extension of the `PcodeEmulator`.
It is polite to compose your library with the one already provided by the super class, lest you remove userops and cause unexpected crashes later.
For the sake of demonstration, we have included an injection that uses the custom library, and we have included a monitored loop to execute a single thread indefinitely.
The initialization of the machine and its one thread is left to the script writer.
The emulation *is not* implicitly associated with the program!
You must copy the program image into its state, and you should choose a different location for the injection.
Refer to the example scripts in Ghidra's `SystemEmulation` module.

If you would like to (temporarily) override the GUI with a custom userop library, you can by overriding the GUI's emulator factory:

```java {.numberLines}
public class InstallCustomLibraryScript extends GhidraScript implements FlatDebuggerAPI {
	public static class CustomBytesDebuggerPcodeEmulator extends BytesDebuggerPcodeEmulator {
		private CustomBytesDebuggerPcodeEmulator(PcodeDebuggerAccess access) {
			super(access);
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			return super.createUseropLibrary()
					.compose(new ModelingScript.SleighStdLibPcodeUseropLibrary<>(
						(SleighLanguage) access.getLanguage()));
		}
	}

	public static class CustomBytesDebuggerPcodeEmulatorFactory
			extends BytesDebuggerPcodeEmulatorFactory {
		@Override
		public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
			return new CustomBytesDebuggerPcodeEmulator(access);
		}
	}

	@Override
	protected void run() throws Exception {
		getEmulationService().setEmulatorFactory(new CustomBytesDebuggerPcodeEmulatorFactory());
	}
}
```

This will make your custom userops available in Sleigh injections.
**NOTE**: There is currently no way to introduce custom userops to Watches or the Go To dialog.

## Modeling Arithmetic Operations

The remaining sections deal in modeling things other than concrete emulation.
In most dynamic analysis cases, we will *augment* a concrete emulator with some other abstract execution model, e.g., for dynamic taint analysis or concolic emulation.
Ghidra's emulation framework favors the composition of execution models.
This allows you to focus on the abstract execution model and later compose it with the concrete model to form the full augmented model.
This also facilitates the creation of re-usable components, but that still requires some forethought.

Modeling the arithmetic is fairly straightforward.
For demonstration we will develop a model for building up symbolic expressions.
The idea is that after doing some number of steps of emulation, the user can examine not only the concrete value of a variable, but the expression that generated it in terms of the variables at the start of the stepping schedule.
We *will not* attempt to simplify or otherwise analyze these expressions.
For that, you would want to use a proper SMT, which is beyond the scope of this tutorial.

### The Model

We will represent constants as literals, and then build up expression trees as each operation is applied.
The number of operators can get extensive, and your particular use case / target may not require all of them.
That said, if you intend for your model to be adopted broadly, you should strive for as complete an implementation as reasonably possible.
At the very least, strive to provide extension points where you predict the need to alter or add features.
In this tutorial, we will elide all but what is necessary to illustrate the implementation.

If it is not already provided to you by your dependencies, you will need to devise the actual model.
These need not extend from nor implement any Ghidra-specific interface, but they can.

```java {.numberLines}
public class ModelingScript extends GhidraScript {
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

	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub

	}
}
```

It should be fairly apparent how you could add more expression types to complete the model.
There is some odd nuance in the naming of p-code operations, so do read the documentation carefully.
If you are not entirely certain what an operation does, take a look at [OpBehaviorFactory](../../../Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/pcode/opbehavior/OpBehaviorFactory.java).
You can also examine the concrete implementation on byte arrays [BytesPcodeArithmetic](../../../Ghidra/Framework/Emulation/src/main/java/ghidra/pcode/exec/BytesPcodeArithmetic.java).

### Mapping the Model

Now, to map the model to p-code, we implement the `PcodeArithmetic` interface.
In many cases, the implementation can be an enumeration: one for big endian and one for little endian.
Rarely, it can be a singleton.
Conventionally, you should also include static methods for retrieving an instance by endianness or processor language:

```java {.numberLines}
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
```

We have implemented two arithmetic models: one for big-endian languages and one for little-endian.
The endianness comes into play when we encode constant values passed to `fromConst()`.
We must convert the `byte[]` value to a big integer accordingly.
The choice of `BigInteger` is merely a matter of preference; you could easily just have `LitExpr` encapsulate the `byte[]` and worry about how to interpret them later.
We also override all implementations of `fromConst()` to avoid the back-and-forth conversion between `BigInteger` and `byte[]`.

The implementations of `unaryOp()` and `binaryOp()` are straightforward.
Just switch on the opcode and construct the appropriate expression.
This is a place where you might want to provide extensibility.

**NOTE**: If you would like to capture location information, i.e., what instruction performed this operation, then you can override the default `unaryOp()` and `binaryOp()` methods, which receive the actual `PcodeOp` object.
You can get both the opcode and the sequence number (address, index) from that `PcodeOp`.
The ones with signatures taking the integer opcode can just throw an `AssertionError`.

The implementations of `modBeforeStore()` and `modAfterLoad()` are stubs.
They provide an opportunity to capture dereferencing information.
We do not need that information, so we just return the value.
The `mod` methods tread a bit into storage and addressing, which we cover more thoroughly later, but they model memory operations to the extent they do not actually require a storage mechanism.
For example, were this a dynamic taint analyzer, we could use `modAfterLoad()` to record that a value was retrieved via a tainted address.
The `inValue` parameter gives the `Expr` actually retrieved from the emulator's storage, and `inAddress` gives the address (really just the `Expr` piece) used to retrieve it.
Conversely, in `modBeforeStore()`, `inValue` gives the value about to be stored, and `inAddress` gives the address used to store it.

We implement neither `toConcrete()` nor `sizeOf()`.
Since we will be augmenting a concrete emulator, these methods will be provided by the concrete piece.
If this model is ever to be used in static analysis, then it may be worthwhile to implement these methods, so the model may be used independently of the concrete emulator.
In that case, the methods should attempt to do as documented but may throw an exception upon failure.

## Modeling Storage, Addressing, and Memory Operations

The emulator's storage model is a `PcodeExecutorState`.
Since we desire an augmented emulator, we will need to provide it a `PcodeExecutorState<Pair<byte[], Expr>>`.
This tells Java the state is capable of working with pairs of concrete state and the abstract model state.
Addresses in that state are also pairs.
For augmented emulation, the storage model often borrows the concrete addressing model; thus, we will use only the `byte[]` element for our addressing.

The composition of states with the same addressing model is common enough that Ghidra provides abstract components to facilitate it.
The relevant interface is `PcodeExecutorStatePiece`, which is the one we actually implement, by extending from `AbstractLongOffsetPcodeExecutorStatePiece`.

**NOTE**: If you do not desire a concrete address model, then you should implement `PcodeExecutorState<Expr>` directly.
A "state" is also "state piece" whose address model is the same as its value model, so states can still be composed.
On one hand, the abstractly-addressed state provides a component that is readily used in both static and dynamic analysis; whereas, the concretely-addressed piece is suited only for dynamic analysis.
On the other hand, you may have some difficulty correlating concrete and abstract pieces during dynamic analysis when aliasing and indirection is involved.

Now for the code.
Be mindful of all the adjectives.
If you are not already familiar with Java naming conventions for "enterprise applications" or our particular implementation of them, you are about to see it on full display.

```java {.numberLines}
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
		return expr != null ? expr : new VarExpr(space, offset, size);
	}
}

public static abstract class AbstractExprPcodeExecutorStatePiece<S extends ExprSpace> extends
		AbstractLongOffsetPcodeExecutorStatePiece<byte[], Expr, S> {

	protected final AbstractSpaceMap<S> spaceMap = newSpaceMap();

	public AbstractExprPcodeExecutorStatePiece(Language language) {
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
		extends AbstractExprPcodeExecutorStatePiece<ExprSpace> {
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
```

The abstract class implements a strategy where a dedicated object handles each address space.
Each object typically maintains of map of offsets (type `long`) to the model type, i.e., `Expr`.
We provide that object type `ExprSpace`, which is where we implement most of our actual storage.

**WARNING**: For the sake of simplicity in demonstration, we have neglected many details.
Notably, we have neglected the possibility that writes overlap or that reads are offcut from the variables actually stored there.
This may not seem like a huge problem, but it is actually quite common, esp., since x86 registers are structured.
A write to `RAX` followed by a read from `EAX` will immediately demonstrate this issue.
Nevertheless, we leave those details as an exercise.

The remaining parts are mostly boilerplate.
We implement the "state piece" interface by creating another abstract class.
An abstract class is not absolutely necessary, but it will be useful when we integrate the model with traces and the Debugger GUI later.
We are given the language and applicable arithmetics, which we just pass to the super constructor.
We need not implement a concrete buffer.
This would only be required if we needed to decode instructions from the abstract storage model.
For dynamic analysis, we would bind concrete buffers from the concrete piece, not the abstract.
For static analysis, you would need to decide whether to just use the statically disassembled instructions or to try decoding from the abstract model.
The `clear()` method is implemented by clearing the map of address spaces.
Note that the abstract implementation does not provide that map for us, so we must provide it and the logic to clear it.
The next three methods are for getting spaces from that map and then setting and getting values in them.
The last method `getRegisterValuesFromSpace()` is more for user inspection, so it need not be implemented, at least not yet.

Finally, we complete the implementation of the state piece with `ExprPcodeExecutorStatePiece`, which provides the actual map and an `ExprSpace` factory method `newSpace()`.
The implementation of `ExprPcodeExecutorState` is simple.
It takes the concrete piece and pairs it with a new piece for our model.

## Model-Specific Userops

We do not cover this deeply, but there are two examples in Ghidra:

* [TaintPcodeUseropLibrary](../../../Ghidra/Debug/TaintAnalysis/src/main/java/ghidra/pcode/emu/taint/TaintPcodeUseropLibrary.java)
* [TaintFileReadsLinuxAmd64SyscallLibrary](../../../Ghidra/Debug/TaintAnalysis/src/main/java/ghidra/pcode/emu/taint/lib/TaintFileReadsLinuxAmd64SyscallLibrary.java)

The first provides a means of marking variables with taint.
Unlike our `Expr` model, which automatically generates a `VarExpr` whenever a variable is read for the first time, the taint analyzer assumes no state is tainted.
You may notice the library does not use a generic `T`, but instead requires `T=Pair<byte[], TaintVec>`.
This will ensure the library is only used with a taint-augmented emulator.

The second demonstrates the ability to extend Ghidra's system call libraries, not only with additional calls, but also with additional models.

## Constructing the Augmented Emulator

Ghidra supports the construction of augmented emulators through the `AuxEmulatorPartsFactory<Expr>` interface.
These are typically singletons.

```java {.numberLines}
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
	protected AuxEmulatorPartsFactory<ModelingScript.Expr> getPartsFactory() {
		return BytesExprEmulatorPartsFactory.INSTANCE;
	}
}
```

Lots of boilerplate.
Essentially, all the parts factory does is give us a flat interface for providing all the parts necessary to construct our augmented emulator: the model arithmetic, userop libraries for the machine and threads, state for the machine and threads.
For the arithmetic, we trivially provide the arithmetic for the given language.
For the userop libraries, we just provide the empty library.
If you had custom libraries and/or model-specific libraries, you would compose them here.
Finally, for the states, we just take the provided concrete state and construct our augmented state.

## Use in Dynamic Analysis

What we have constructed so far is suitable for constructing and using our augmented emulator in a script.
Using it is about as straightforward as the plain concrete emulator.
The exception may be when accessing its state, you will need to be cognizant of the pairing.

```java {.numberLines}
public class ModelingScript extends GhidraScript {

	// ...

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
```

**NOTE**: When accessed as a paired state, all sets will affect both pieces.
If you use the arithmetic to generate them, remember that it will use `fromConst` on both arithmetics to generate the pair, so you may be setting the right side to a `LitExpr`.
To modify just one side of the pair, cast the state to `PairedPcodeExecutorState`, and then use `getLeft()`, and `getRight()` to retrieve the separate pieces.

## Use in Static Analysis

We do not go into depth here, especially since this is not formalized.
There are many foundational utilities not factored out yet.
Nevertheless, for an example where the `PcodeArithmetic` and `PcodeExecutorState` interfaces are used in static analysis, see the Debugger's stack unwinder.
While unwinding a full stack technically qualifies as dynamic analysis, the analysis of each individual function to recover stack frame information is purely static.
See [UnwindAnalysis](../../../Ghidra/Debug/Debugger/src/main/java/ghidra/app/plugin/core/debug/stack/UnwindAnalysis.java) and its sibling files.

## GUI Integration

This part is rather tedious.
It is mostly boilerplate, and the only real functionality we need to provide is a means of serializing `Expr` to the trace database.
Ideally, this serialization is also human readable, since that will make it straightforward to display in the UI.
Typically, there are two more stages of integration.
First is integration with traces, which involves the aforementioned serialization.
Second is integration with targets, which often does not apply to abstract models, but could.
Each stage involves an extension to the lower stage's state.
Java does not allow multiple inheritance, so we will have to be clever in our factoring, but we generally cannot escape the boilerplate.

```java {.numberLines}
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

public static class ExprTracePcodeExecutorStatePiece
		extends AbstractExprPcodeExecutorStatePiece<ExprTraceSpace>
		implements TracePcodeExecutorStatePiece<byte[], Expr> {
	public static final String NAME = "Taint";

	protected final PcodeTraceDataAccess data;
	protected final PcodeTracePropertyAccess<String> property;

	public ExprTracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
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
	public ExprTracePcodeExecutorStatePiece fork() {
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
```

Because we do not need any additional logic for target integration, we do not need to extend the state pieces any further.
The concrete pieces that we augment will contain all the target integration needed.
We have left the serialization as an exercise, though.
Last, we implement the full parts factory and use it to construct and install a full `Expr`-augmented emulator factory:

```java {.numberLines}
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
```

The factory can then be installed using a script.
The script will set your factory as the current emulator factory for the whole tool; however, your script-based factory will not be listed in the menus.
Also, if you change your emulator, you must re-run the script to install those modifications.
You might also want to invalidate the emulation cache.

```java {.numberLines}
public class InstallExprEmulatorScript extends GhidraScript implements FlatDebuggerAPI {
	@Override
	protected void run() throws Exception {
		getEmulationService()
				.setEmulatorFactory(new ModelingScript.BytesExprDebuggerPcodeEmulatorFactory());
	}
}
```

Alternatively, and this is recommended once your emulator is "production ready," you should create a proper Module project using the GhidraDev plugin for Eclipse.
You will need to break all the nested classes from your script out into separate files.
So long as your factory class is public, named with the suffix `DebuggerPcodeEmulatorFactory`, implements the interface, and included in Ghidra's classpath, Ghidra should find and list it in the **Debugger &rarr; Configure Emulator** menu.

### Displaying and Manipulating Abstract State

Once you have an emulator factory, the bulk of the work is done.
However, at this point, users can only interact with the abstract portion of the emulator's state through scripts, or by invoking custom userops in patch steps from the **Go To Time** dialog.
To display the abstract state in the UI, you need to develop two additional components: one for display in the Dynamic Listing (for memory state) and one for display in the Registers window (for register state).
(Display of custom state in the Watches or P-code Stepper panes is not supported.)
Unlike an emulator factory, these components cannot be installed via a script.
They must be provided as classes in a proper Ghidra Module.

Since string-based serialization may be a common case, we may eventually provide abstract implementations to make that case easy.
For now, we refer you to the implementations for the Taint-augmented emulator:

* For memory state: [TaintFieldFactory](../../../Ghidra/Debug/TaintAnalysis/src/main/java/ghidra/taint/gui/field/TaintFieldFactory.java)
* For regsiter state: [TaintDebuggerRegisterColumnFactory](../../../Ghidra/Debug/TaintAnalysis/src/main/java/ghidra/taint/gui/field/TaintDebuggerRegisterColumnFactory.java)

Anything more than that would require completely custom providers, plugins, etc.