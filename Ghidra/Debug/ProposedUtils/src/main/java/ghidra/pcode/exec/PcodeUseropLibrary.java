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

import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.util.*;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.pcode.Varnode;
import ghidra.sleigh.grammar.Location;

/**
 * A "library" of p-code userops available to a p-code executor
 *
 * <p>
 * The library can provide definitions of p-code userops already declared by the executor's language
 * as well as completely new userops accessible to Sleigh/p-code later compiled for the executor.
 * The recommended way to implement a library is to extend {@link AnnotatedPcodeUseropLibrary}.
 *
 * @param <T> the type of values accepted by the p-code userops.
 */
public interface PcodeUseropLibrary<T> {
	/**
	 * The class of the empty userop library.
	 * 
	 * @see {@link PcodeUseropLibrary#nil()}
	 */
	final class EmptyPcodeUseropLibrary implements PcodeUseropLibrary<Object> {
		@Override
		public Map<String, PcodeUseropDefinition<Object>> getUserops() {
			return Map.of();
		}
	}

	/**
	 * Get the type {@code T} for the given class
	 * 
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
	 * 
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
		 * 
		 * <p>
		 * This is the symbol assigned to the userop when compiling new SLEIGH code. It cannot
		 * conflict with existing userops (except those declared, but not defined, by the executor's
		 * language) or other symbols of the executor's language. If this userop is to be used
		 * generically across many languages, choose an unlikely name. Conventionally, these start
		 * with two underscores {@code __}.
		 * 
		 * @return the name of the userop
		 */
		String getName();

		/**
		 * Get the number of <em>input</em> operands acccepted by the userop.
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
		 * @param outVar if invoked as an rval, the destination varnode for the userop's output.
		 *            Otherwise, {@code null}.
		 * @param inVars the input varnodes as ordered in the source.
		 * @see AnnotatedPcodeUseropLibrary.AnnotatedPcodeUseropDefinition
		 */
		void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library, Varnode outVar,
				List<Varnode> inVars);
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
	 * @return a new library having all userops defined between the two
	 */
	default PcodeUseropLibrary<T> compose(PcodeUseropLibrary<T> lib) {
		if (lib == null) {
			return this;
		}
		return new ComposedPcodeUseropLibrary<>(List.of(this, lib));
	}

	/**
	 * Get named symbols defined by this library that are not already declared in the language
	 * 
	 * @param language the language whose existing symbols to consider
	 * @return a map of new userop indices to extra userop symbols
	 */
	default Map<Integer, UserOpSymbol> getSymbols(SleighLanguage language) {
		//Set<String> langDefedNames = new HashSet<>();
		Map<Integer, UserOpSymbol> symbols = new HashMap<>();
		Set<String> allNames = new HashSet<>();
		int langOpCount = language.getNumberOfUserDefinedOpNames();
		for (int i = 0; i < langOpCount; i++) {
			String name = language.getUserDefinedOpName(i);
			allNames.add(name);
		}
		int nextOpNo = langOpCount;
		for (PcodeUseropDefinition<?> uop : new TreeMap<>(getUserops()).values()) {
			String opName = uop.getName();
			if (!allNames.add(opName)) {
				// Real duplicates will cause a warning during execution
				continue;
			}

			int opNo = nextOpNo++;
			Location loc = new Location(getClass().getName() + ":" + opName, 0);
			UserOpSymbol sym = new UserOpSymbol(loc, opName);
			sym.setIndex(opNo);
			symbols.put(opNo, sym);
		}
		return symbols;
	}
}
