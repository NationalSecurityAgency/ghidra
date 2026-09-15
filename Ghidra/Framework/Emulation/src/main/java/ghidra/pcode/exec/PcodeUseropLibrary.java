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

import java.lang.reflect.*;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol;
import ghidra.lifecycle.Internal;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.OpOutput;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.PcodeUserop;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.lang.PcodeParser;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A "library" of p-code userops available to a p-code executor
 * <p>
 * The library can provide definitions of p-code userops already declared by the executor's language
 * as well as completely new userops accessible to Sleigh/p-code later compiled for the executor.
 * The recommended way to implement a library is to extend {@link AnnotatedPcodeUseropLibrary}.
 *
 * @param <T> the type of values accepted by the p-code userops.
 */
public interface PcodeUseropLibrary<T> {

	/**
	 * A store of userop symbols, retrievable by index or name
	 * 
	 * @param language the language whose symbols are incorporated into retrieval
	 * @param byIndex the symbols by index, excluding those in the language already
	 * @param byName the symbols by name, excluding those in the language already
	 */
	record PcodeUseropSymbolMap(SleighLanguage language, Map<Integer, UserOpSymbol> byIndex,
			Map<String, UserOpSymbol> byName) {
		public PcodeUseropSymbolMap {
			if (!byIndex.isEmpty() || !byName.isEmpty()) {
				Objects.requireNonNull(language);
			}
		}

		/**
		 * The empty set of symbols
		 */
		public static final PcodeUseropSymbolMap EMPTY =
			new PcodeUseropSymbolMap(null, Map.of(), Map.of());

		private static Map<String, UserOpSymbol> byName(Map<Integer, UserOpSymbol> byIndex) {
			return byIndex.values()
					.stream()
					.collect(Collectors.toMap(s -> s.getName(), s -> s));
		}

		/**
		 * Construct a store from the language and symbols by index
		 * <p>
		 * This constructor re-indexes by name as well to create the full store
		 * 
		 * @param language the language whose symbols are incorporated into retrieval
		 * @param byIndex the symbols by index, excluding those in the language already
		 */
		public PcodeUseropSymbolMap(SleighLanguage language, Map<Integer, UserOpSymbol> byIndex) {
			this(language, byIndex, byName(byIndex));
		}

		/**
		 * Get the name of a userop by its index, whether from the language or library
		 * 
		 * @param index the index
		 * @return the name, or null
		 */
		public String getUseropName(int index) {
			if (language == null) {
				return null;
			}
			if (index < language.getNumberOfUserDefinedOpNames()) {
				return language.getUserDefinedOpName(index);
			}
			UserOpSymbol symbol = byIndex.get(index);
			return symbol == null ? null : symbol.getName();
		}

		/**
		 * Get the index of a userop by its name, whether from the language or library
		 * 
		 * @param name the name
		 * @return the index, or -1
		 */
		public int getUseropIndex(String name) {
			if (language == null) {
				return -1;
			}
			// Oof. UseropSymbol and UserOpSymbol in the same source file!
			if (language.getSymbolTable().findSymbol(name) instanceof UseropSymbol userop) {
				return userop.getIndex();
			}
			UserOpSymbol symbol = byName.get(name);
			return symbol == null ? -1 : symbol.getIndex();
		}

		/**
		 * Add the library symbols to a given parser
		 * 
		 * @param parser the parser whose table to populate
		 */
		public void addToParser(PcodeParser parser) {
			for (UserOpSymbol sym : byIndex.values()) {
				parser.addSymbol(sym);
			}
		}
	}

	/**
	 * A cache of symbols per library
	 */
	@Internal
	Map<PcodeUseropLibrary<?>, SymbolsCache> SYMBOL_CACHE = new WeakHashMap<>();

	/**
	 * The class of the empty userop library.
	 * 
	 * @see PcodeUseropLibrary#nil()
	 */
	final class EmptyPcodeUseropLibrary implements PcodeUseropLibrary<Object> {
		@Override
		public Map<String, PcodeUseropDefinition<Object>> getUserops() {
			return Map.of();
		}

		@Override
		public PcodeUseropLibrary<Object> compose(PcodeUseropLibrary<Object> lib) {
			return lib;
		}
	}

	/**
	 * Get the type {@code T} for the given class
	 * <p>
	 * If the class does not implement {@link PcodeUseropLibrary}, this returns null. If it does,
	 * but no arguments are given (i.e., it implements the raw type), this return {@link Object}.
	 * 
	 * @param cls the class
	 * @return the type, or null
	 */
	static Type getOperandType(Class<?> cls) {
		Map<TypeVariable<?>, Type> args =
			TypeUtils.getTypeArguments(cls, PcodeUseropLibrary.class);
		if (args == null) {
			return null;
		}
		if (args.isEmpty()) {
			return Object.class;
		}
		return args.get(PcodeUseropLibrary.class.getTypeParameters()[0]);
	}

	/**
	 * The empty userop library.
	 * <p>
	 * Executors cannot accept {@code null} libraries. Instead, give it this empty library. To
	 * satisfy Java's type checker, you may use {@link #nil()} instead.
	 */
	PcodeUseropLibrary<?> NIL = new EmptyPcodeUseropLibrary();

	/**
	 * The empty userop library, cast to match parameter types.
	 * 
	 * @param <T> the type required by the executor
	 * @return the empty userop library
	 */
	@SuppressWarnings("unchecked")
	public static <T> PcodeUseropLibrary<T> nil() {
		return (PcodeUseropLibrary<T>) NIL;
	}

	/**
	 * The definition of a p-code userop.
	 *
	 * @param <T> the type of parameter accepted (and possibly returned) by the userop.
	 */
	interface PcodeUseropDefinition<T> {
		/**
		 * Get the name of the userop.
		 * <p>
		 * This is the symbol assigned to the userop when compiling new Sleigh code. It cannot
		 * conflict with existing userops (except those declared, but not defined, by the executor's
		 * language) or other symbols of the executor's language. If this userop is to be used
		 * generically across many languages, choose an unlikely name. Conventionally, these start
		 * with two underscores {@code __}.
		 * 
		 * @return the name of the userop
		 */
		String getName();

		/**
		 * Get the number of <em>input</em> operands accepted by the userop.
		 * 
		 * @return the count or -1 if the userop is variadic
		 */
		int getInputCount();

		/**
		 * Invoke/execute the userop.
		 * 
		 * @param executor the executor invoking this userop.
		 * @param library the complete library for this execution. Note the library may have been
		 *            composed from more than the one defining this userop.
		 * @param op the {@link PcodeOp#CALLOTHER} op
		 * @param outVar if invoked as an rval, the destination varnode for the userop's output.
		 *            Otherwise, {@code null}.
		 * @param inVars the input varnodes as ordered in the source.
		 * @see AnnotatedPcodeUseropLibrary.AnnotatedPcodeUseropDefinition
		 */
		void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library, PcodeOp op,
				Varnode outVar, List<Varnode> inVars);

		/**
		 * Invoke/execute the raw userop.
		 * <p>
		 * <b>NOTE:</b> The first input to the raw p-code op is the id of this userop. The userop
		 * inputs are thus at indices 1..N.
		 * 
		 * @param executor the executor invoking this userop.
		 * @param library the complete library for this execution. Note the library may have been
		 *            composed from more than the one defining this userop.
		 * @param op the {@link PcodeOp#CALLOTHER} op
		 */
		default void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library, PcodeOp op) {
			execute(executor, library, op, op.getOutput(),
				Arrays.asList(op.getInputs()).subList(1, op.getNumInputs()));
		}

		/**
		 * Indicates whether this userop is a "pure function."
		 * <p>
		 * This means all inputs are given in the arguments to the userop; and the output, if
		 * applicable, is given via the return. Technically, this is only with respect to the
		 * emulated machine state. If the library carries its own state, and the userop is stateful
		 * with respect to the library, it is still okay to set this to true. When this is set to
		 * false, the underlying execution engine must ensure the machine state is consistent,
		 * because the userop may access any part of it directly. Functional userops ought to take
		 * primitive parameters and return primitives, and should receive neither the executor nor
		 * its state object.
		 * <p>
		 * <b>WARNING:</b> The term "inputs" include disassembly context. Unfortunately, there is
		 * currently no way to access that context via p-code ops generated by Sleigh, so the only
		 * way to obtain it is to ask the emulator thread for it out of band. Userops that require
		 * this are <em>not</em> "pure functions."
		 * 
		 * @return true if a pure function.
		 * @see PcodeUserop#functional()
		 */
		boolean isFunctional();

		/**
		 * Indicates whether this userop can interrupt execution.
		 * <p>
		 * Optimized execution engines seeks to remove unnecessary variable assignments,
		 * computations, etc. If the userop is {@linkplain #isFunctional() functional}, then the
		 * engine can confidently assume only its operands need to be visible at the time of its
		 * invocation. If a userop can interrupt execution, then the engine must assure that, once
		 * the client has handled the exception, the machine state reflects the state at the time of
		 * the interruption. (This is especially critical for user breakpoints.)
		 * <p>
		 * NOTE: We're not settled on the case of "unexpected" interrupts, e.g., a null pointer
		 * exception in a user's userop library. In a sense, this is undefined behavior, so who's to
		 * say the machine had better have a consistent state? On the other hand, for userops that
		 * intend to throw exceptions as a means of interrupting execution for client inspection and
		 * possible resumption, this attribute must be set. Here's the rule for now: <blockquote>If
		 * the intent is to permit the client to resume execution after the interrupt, the machine
		 * state must be consistent, and so this attribute must be true.</blockquote> Otherwise, the
		 * value is set at the userop developer's discretion, but false should be preferred to
		 * facilitate better performance.
		 * 
		 * @return true if the userop can be expected to interrupt execution by throwing an
		 *         exception
		 * @see PcodeUserop#canInterrupt()
		 */
		boolean canInterrupt();

		/**
		 * Indicates whether this userop may have side effects.
		 * <p>
		 * This means that the function may have an output or an effect other than returning a
		 * value. Even if {@link #isFunctional()} is true, it is possible for a userop to have side
		 * effects, e.g., updating a field in a library or printing to the screen. This <em>does
		 * not</em> permit a functional userop to modify the emulated machine state, but only
		 * "out-of-band" state.
		 * 
		 * @return true if it has side effects.
		 * @see PcodeUserop#hasSideEffects()
		 */
		boolean hasSideEffects();

		/**
		 * Indicates that this userop may modify the decode context.
		 * <p>
		 * This means that the userop may set a field in {@code contextreg}, which could thus affect
		 * how subsequent instructions are decoded. Executors which decode ahead will have to
		 * consider this effect.
		 * 
		 * @return true if this can modify the context.
		 * @see PcodeUserop#modifiesContext()
		 */
		boolean modifiesContext();

		/**
		 * Indicates whether or not this userop definition produces p-code suitable for inlining in
		 * place of its invocation.
		 * <p>
		 * Generally, if all the userop definition does is feed additional p-code to the executor
		 * with the same userop library, then it is suitable for inlining. It is possible for the
		 * p-code to depend on other factors, but care must be taken, since the decision could be
		 * fixed by the underlying execution system at any time. E.g., if the p-code is translated
		 * to JVM byte code, then the userop may be inlined at translation time rather than
		 * execution time. Recommended factors include configuration, placement within surrounding
		 * instructions, static analysis, etc., but the p-code should probably not depend on the
		 * machine's dynamic run-time state.
		 * 
		 * @return true if inlining is possible, false otherwise.
		 * @see PcodeUserop#canInline()
		 */
		boolean canInlinePcode();

		/**
		 * Indicates whether the output should be sign or zero extended to match the output varnode
		 * size.
		 * <p>
		 * This only applies when the userop is implemented as a Java function returning a primitive
		 * type. Otherwise, the userop should examine the output varnode and behave accordingly, or
		 * just inline use of that output varnode. When returning, e.g., an {@code int}, it could
		 * happen that the output varnode size 8. Because it's larger, we need to know whether or
		 * not the output is meant to be signed. Contrary to Java conventions, but inline with
		 * Sleigh conventions, we default to <em>false</em>.
		 * 
		 * @return true for signed extension
		 */
		boolean isOutSigned();

		/**
		 * Indicates whether a given input 0-up should be sign or zero extended to match a Java
		 * primitive parameter size.
		 * <p>
		 * This only applies when the userop is implemented as a Java function and this input is
		 * taken as a primitive type. Otherwise, the userop should examine the input varnode and
		 * behave accordingly, or just inline use of that input varnode. When accepting, e.g., a
		 * {@code long}, it could happen the input varnode is size 2. Because it's smaller, we need
		 * to know whether or not that input is meant to be signed. Contrary to Java conventions,
		 * but inline with Sleigh conventions, we default to <em>false</em>.
		 * <p>
		 * <b>WARNING:</b> Constant varnodes can behave weirdly when interpreted as signed. A userop
		 * declaring a signed input must be prepared to deal with this case. Consider the constant
		 * 0x80. Sleigh will encode this as the varnode {@code (const, 0x80, 1)}, i.e., the constant
		 * with value 0x80 having size 1. If you mark an {@code int} input as signed, and it
		 * receives this constant, Java will see it as -128.
		 * 
		 * @param index the position of the input argument, 0 is leftmost.
		 * @return true for signed extension
		 */
		boolean isInSigned(int index);

		/**
		 * If this userop is defined as a java callback, get the type of the output
		 * <p>
		 * If the method has a {@code @}{@link OpOutput} annotation, this is the type of the output
		 * parameter. Otherwise, this is the method's return type.
		 * 
		 * @return the output type
		 */
		Class<?> getOutputType();

		/**
		 * If this userop is defined as a java callback, get the method
		 * 
		 * @return the method, or null
		 */
		Method getJavaMethod();

		/**
		 * Get the library that defines (or "owns") this userop
		 * <p>
		 * A userop can become part of other composed libraries, so the library from which this
		 * userop was retrieved may not be the same as the one that defined it. This returns the one
		 * that defined it.
		 * <p>
		 * As a special consideration, if this userop is a wrapper around another, and this wrapper
		 * returns the java method of the delegate, this <em>must</em> return the defining library
		 * of the delegate. If this is not defined by a java callback, this method (the defining
		 * library) may be null.
		 * 
		 * @return the defining library
		 */
		PcodeUseropLibrary<?> getDefiningLibrary();
	}

	/**
	 * Get all the userops defined in this library, keyed by (symbol) name.
	 * 
	 * @return the map of names to defined userops
	 */
	Map<String, PcodeUseropDefinition<T>> getUserops();

	/**
	 * Compose this and the given library into a new library.
	 * 
	 * @param lib the other library
	 * @param override allow the given library to override userops from this library
	 * @return a new library having all userops defined between the two
	 */
	default PcodeUseropLibrary<T> compose(PcodeUseropLibrary<T> lib, boolean override) {
		if (lib == null || lib == NIL) {
			return this;
		}
		return new ComposedPcodeUseropLibrary<>(List.of(this, lib), override);
	}

	/**
	 * Compose this and the given library into a new library, forbidding overrides
	 * 
	 * @param lib the other library
	 * @return a new library having all userops defined between the two
	 */
	default PcodeUseropLibrary<T> compose(PcodeUseropLibrary<T> lib) {
		return compose(lib, false);
	}

	/**
	 * Get named symbols defined by this library that are not already declared in the language
	 * 
	 * @param language the language whose existing symbols to consider
	 * @return a map of new userop indices to extra userop symbols
	 * @implNote implementors would be wise to cache these by language
	 */
	default PcodeUseropSymbolMap getSymbols(SleighLanguage language) {
		SymbolsCache cache;
		synchronized (SYMBOL_CACHE) {
			cache = SYMBOL_CACHE.computeIfAbsent(this, SymbolsCache::new);
		}
		return cache.getSymbols(language);
	}
}
