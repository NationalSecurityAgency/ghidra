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

import java.lang.annotation.*;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A discoverable factory for creating a pluggable userop library, automatically picked up by the
 * default emulator.
 * 
 * <p>
 * The factory must have a public default constructor.
 */
public interface PcodeUseropLibraryFactory extends ExtensionPoint {
	public static final int DEFAULT_ORDER = 100;
	/** The property key for useropLib ids in pspec files */
	public static final String KEY_USEROP_LIBS = GhidraLanguagePropertyKeys.USEROP_LIBS;

	/**
	 * A required annotation for identifying the library in pspec files
	 */
	@Target(ElementType.TYPE)
	@Retention(RetentionPolicy.RUNTIME)
	@interface UseropLibrary {
		/**
		 * The id of this library (factory)
		 * 
		 * <p>
		 * This id should not contain any commas. While other symbols are allowed, only hyphens and
		 * periods are recommended. We request all unqualified ids be reserved for use by the core
		 * Ghidra distribution. Extensions, scripts, and other 3rd-party additions should use
		 * periods to briefly qualify their names, e.g., {@code "com.example.my-userop-lib"}.
		 * 
		 * @return the id
		 */
		String id();

		/**
		 * Specifies whether this library is always included, regardless of the id
		 * 
		 * @return true to include always
		 */
		boolean includeAlways() default false;

		/**
		 * Determines in what order overrides are applied
		 * <p>
		 * Higher values are applied later, and thus take precedence.
		 * 
		 * @return the override order
		 */
		int order() default DEFAULT_ORDER;
	}

	/**
	 * Create the userop library as identified for the given language and arithmetic
	 * 
	 * <p>
	 * While not strictly enforced by the framework, some care should be taken to ensure the library
	 * is prepared to handle the given language, since it may only expect those whose pspec files
	 * identify it. The library (or its factory) may throw an exception, or otherwise exhibit
	 * undefined behavior, if it cannot find the resources, e.g., a specific named register, that it
	 * expects.
	 * 
	 * <p>
	 * The given arithmetic must also be compatible with both the library and the language. In
	 * particular, the language and arithmetic must agree in endianness. (The default emulator
	 * should already ensure this is the case.) The library must also understand the type of the
	 * arithmetic, i.e., the type of values in the emulator. If either is not the case the emulator
	 * may exhibit undefined behavior. (The default emulator does <em>not</em> guarantee type
	 * compatibility.) Ideally, such incompatibilities are checked and reported by the userop
	 * library as early as possible, e.g., in the library's constructor.
	 * 
	 * <p>
	 * If the given id cannot be found, an empty library ({@link PcodeUseropLibrary#nil()}) is
	 * returned and a warning logged. If multiple factories have the given id (this is considered a
	 * bug), then a warning is logged and a factory is selected non-deterministically.
	 * 
	 * @param <T> the type of values in the emulator's state
	 * @param id the id of the userop library
	 * @param language the language
	 * @param arithmetic the arithmetic
	 * @return the userop library
	 */
	static <T> PcodeUseropLibrary<T> createUseropLibraryFromId(String id, SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		List<PcodeUseropLibraryFactory> matches =
			ClassSearcher.getInstances((PcodeUseropLibraryFactory.class))
					.stream()
					.filter(f -> Objects.equals(id, f.getId()))
					.toList();
		if (matches.isEmpty()) {
			Msg.warn(PcodeUseropLibraryFactory.class, "No userop library with the id: " + id);
			return PcodeUseropLibrary.nil();
		}
		if (matches.size() > 1) {
			Msg.warn(PcodeUseropLibraryFactory.class,
				"Multiple userop libraries with the id: " + id + ". Selection is undefined.");
		}
		return matches.getFirst().create(language, arithmetic);
	}

	/**
	 * Create the userop library for the given language
	 * 
	 * <p>
	 * This composes all of the libraries named in the language's pspec file in the
	 * {@value #KEY_USEROP_LIBS} property. That property is a comma-separated list of the
	 * {@link UseropLibrary#id() ids} to compose. The composition also includes libraries marked as
	 * {@link UseropLibrary#includeAlways}. Once all included libraries are identified, they are
	 * sorted by {@link UseropLibrary#order()} and composed, overriding duplicate userops.
	 * 
	 * <p>
	 * See the caveats in
	 * {@link #createUseropLibraryFromId(String, SleighLanguage, PcodeArithmetic)} regarding
	 * agreement between language and arithmetic.
	 * 
	 * @param <T> the type of values in the emulator's state
	 * @param language the language
	 * @param arithmetic the arithmetic
	 * @return the userop library
	 */
	static <T> PcodeUseropLibrary<T> createUseropLibraryForLanguage(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		List<String> libIds = List.of(language.getProperty(KEY_USEROP_LIBS, "").split(","));
		List<PcodeUseropLibraryFactory> matches =
			ClassSearcher.getInstances(PcodeUseropLibraryFactory.class)
					.stream()
					.filter(f -> f.isIncludeAlways() || libIds.contains(f.getId()))
					.sorted(Comparator.comparing(f -> f.getOrder()))
					.toList();
		PcodeUseropLibrary<T> result = PcodeUseropLibrary.nil();
		for (PcodeUseropLibraryFactory factory : matches) {
			result = result.compose(factory.create(language, arithmetic), true);
		}
		return result;
	}

	default UseropLibrary getAnnotation() {
		UseropLibrary annot = this.getClass().getAnnotation(UseropLibrary.class);
		if (annot == null) {
			Msg.warn(this,
				"%s %s is missing @%s annotation".formatted(
					PcodeUseropLibraryFactory.class.getSimpleName(), this.getClass(),
					UseropLibrary.class.getSimpleName()));
		}
		return annot;
	}

	/**
	 * Get the id of this factory
	 * <p>
	 * This gets {@link UseropLibrary#id()} from the annotation. You should not override this
	 * function without a good reason.
	 * 
	 * @return the id
	 */
	default String getId() {
		UseropLibrary annot = getAnnotation();
		return annot == null ? null : annot.id();
	}

	/**
	 * Check if this factory's library should always be included.
	 * <p>
	 * This gets {@link UseropLibrary#includeAlways()} from the annotation. You should not override
	 * this function without a good reason.
	 * 
	 * @return true if always included
	 */
	default boolean isIncludeAlways() {
		UseropLibrary annot = getAnnotation();
		return annot == null ? false : annot.includeAlways();
	}

	/**
	 * Get the override order of this library.
	 * <p>
	 * This gets {@link UseropLibrary#order()} from the annotation. You should not override this
	 * function without a good reason.
	 * 
	 * @return the order
	 */
	default int getOrder() {
		UseropLibrary annot = getAnnotation();
		return annot == null ? DEFAULT_ORDER : annot.order();
	}

	/**
	 * Create the userop library
	 * 
	 * @param <T> the type of values in the emulator
	 * @param language the language of the emulator
	 * @param arithmetic the arithmetic of the emulator
	 * @return the userop library
	 */
	<T> PcodeUseropLibrary<T> create(SleighLanguage language, PcodeArithmetic<T> arithmetic);
}
