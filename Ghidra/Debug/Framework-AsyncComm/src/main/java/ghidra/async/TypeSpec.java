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
package ghidra.async;

import java.util.*;
import java.util.concurrent.Future;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.async.seq.AsyncSequenceWithoutTemp;

/**
 * An interface for type specification in sequences
 *
 * This is just fodder for Java's generic type system. Sometimes it is not intelligent enough to
 * resolve a type parameter, especially when passing a lambda function. A workaround, albeit
 * hackish, is to add an unused argument to aid resolution. Take for example, the utility method
 * {@link AsyncUtils#sequence(TypeSpec)}. It returns a {@link AsyncSequenceWithoutTemp}{@code <R>}.
 * Were it not for the argument {@code TypeSpec<R> type}, Java could only resolve {@code <R>} by
 * assigning the sequence to a temporary variable. This would require an extra line for the
 * assignment, including the full specification of the type, e.g.:
 * 
 * <pre>
 * AsyncSequenceWithoutTemp<Integer> s = sequence().then((seq) -> {
 * 	// Do stuff
 * });
 * return s.asCompletableFuture();
 * </pre>
 * 
 * However, this makes the definition exceedingly verbose, and it exposes the implementation
 * details. While the unused argument is a nuisance, it is preferred to the above alternative. Thus,
 * the static methods in this class seek to ease obtaining an appropriate {@code TypeSpec}. Several
 * primitive and common types are pre-defined.
 * 
 * This interface is not meant to be implemented by any classes or extended by other interfaces. The
 * runtime value of a {@code TypeSpec} argument is always {@link #RAW}. The arguments only serve a
 * purpose at compile time.
 * 
 * TODO: Look at TypeLiteral instead....
 * 
 * @param <U> the type of this specification
 */
public interface TypeSpec<U> {
	@SuppressWarnings("rawtypes")
	public static final TypeSpec RAW = new TypeSpec() {
		/*
		 * Nothing to put here. This one instance will just be cast to satisfy the compiler. I wish
		 * this didn't blow runtime cycles.
		 */
	};
	public static final TypeSpec<Object> OBJECT = auto();
	public static final TypeSpec<Boolean> BOOLEAN = auto();
	public static final TypeSpec<Byte> BYTE = auto();
	public static final TypeSpec<Character> CHAR = auto();
	public static final TypeSpec<Short> SHORT = auto();
	public static final TypeSpec<Integer> INT = auto();
	public static final TypeSpec<Long> LONG = auto();
	public static final TypeSpec<String> STRING = auto();
	public static final TypeSpec<Void> VOID = auto();

	public static final TypeSpec<byte[]> BYTE_ARRAY = auto();

	/**
	 * Obtain the most concrete type specifier suitable in the context
	 * 
	 * This is a sort of syntactic filler to satisfy Java's type checker while carrying useful type
	 * information from action to action of an asynchronous sequence. This method is likely
	 * preferred for all cases. The cases where this is not used are equivalent to the explicit use
	 * of type annotations in normal synchronous programming. Either the programmer would like to
	 * ensure an intermediate result indeed has the given type, or the programmer would like to
	 * ascribe a more abstract type to the result.
	 * 
	 * NOTE: For some compilers, this doesn't work in all contexts. It tends to work in Eclipse, but
	 * not in Gradle when used with directly
	 * {@link AsyncSequenceWithoutTemp#then(java.util.concurrent.Executor, ghidra.async.seq.AsyncSequenceActionProduces, TypeSpec)}.
	 * Not sure what compiler option(s) are causing the difference.
	 * 
	 * @return
	 */
	@SuppressWarnings({ "unchecked" })
	public static <T> TypeSpec<T> auto() {
		return RAW;
	}

	public static <T> TypeSpec<T> from(Future<T> future) {
		return auto();
	}

	/**
	 * Obtain a type specifier of a given raw class type
	 * 
	 * @param cls the type of the producer
	 * @return the specifier
	 */
	public static <U> TypeSpec<U> cls(Class<U> cls) {
		return auto();
	}

	/**
	 * Obtain a type specifier of a type given by an example
	 * 
	 * @param example the example having the desired type, often {@code null} cast to the type
	 * @return the specifier
	 */
	public static <U> TypeSpec<U> obj(U example) {
		return auto();
	}

	/**
	 * Obtain a type specifier for a collection of this type
	 * 
	 * @return the collection specifier
	 */
	public default <C extends Collection<U>> TypeSpec<C> col() {
		return auto();
	}

	/**
	 * Obtain a type specifier for a given collection type of this type
	 * 
	 * @param <C> the type of collection
	 * @param cls the raw type of the collection
	 * @return the collection specifier
	 */
	public default <C extends Collection<U>> TypeSpec<C> col(Class<? super C> cls) {
		return auto();
	}

	/**
	 * Obtain a type specifier for a set of this type
	 * 
	 * @return the collection specifier
	 */
	public default <C extends Set<U>> TypeSpec<C> set() {
		return auto();
	}

	/**
	 * Obtain a type specifier for a list of this type
	 * 
	 * @return the collection specifier
	 */
	public default <C extends List<U>> TypeSpec<C> list() {
		return auto();
	}

	/**
	 * Obtain a type specifier for a list of this type
	 * 
	 * @return the collection specifier
	 */
	/*public default <C extends List<? extends U>> TypeSpec<C> listExt() {
		return auto();
	}*/

	/**
	 * Object a type specifier which allows extensions of this type
	 * 
	 * @return the "extends" type specifier
	 */
	public default TypeSpec<? extends U> ext() {
		return auto();
	}

	/**
	 * Obtain a type specifier for a map from the given type to this type
	 * 
	 * @param <K> the type of key
	 * @param keyType the type specifier for the keys
	 * @return the map type specifier
	 */
	public default <K> TypeSpec<Map<K, U>> mappedBy(TypeSpec<K> keyType) {
		return auto();
	}

	/**
	 * Obtain a type specifier for a map from the given class to this type
	 * 
	 * @param <K> the type of key
	 * @param keyCls the class for the keys
	 * @return the map type specifier
	 */
	public default <K> TypeSpec<Map<K, U>> mappedBy(Class<K> keyCls) {
		return auto();
	}

	/**
	 * Obtain a type specifier of a map given the raw class types for keys and values
	 * 
	 * @param keyCls the type for keys
	 * @param valCls the type for values
	 * @return the specifier
	 */
	public static <K, V> TypeSpec<Map<K, V>> map(Class<K> keyCls, Class<V> valCls) {
		return auto();
	}

	public static <L, R> TypeSpec<Pair<L, R>> pair(TypeSpec<L> lSpec, TypeSpec<R> rSpec) {
		return auto();
	}

	/**
	 * An interface for methods of 0 arguments
	 *
	 * @param <R> the return type of the method
	 */
	interface FuncArity0<R> {
		R func();
	}

	/**
	 * An interface for methods of 1 argument
	 *
	 * @param <R> the return type of the method
	 * @param <P0> the type of the first parameter
	 */
	interface FuncArity1<R, P0> {
		R func(P0 arg0);
	}

	/**
	 * An interface for methods of 2 arguments
	 *
	 * @param <R> the return type of the method
	 * @param <P0> the type of the first parameter
	 * @param <P1> the type of the second parameter
	 */
	interface FuncArity2<R, P0, P1> {
		R func(P0 arg0, P1 arg1);
	}

	/**
	 * An interface for methods of 3 arguments
	 *
	 * @param <R> the return type of the method
	 * @param <P0> the type of the first parameter
	 * @param <P1> the type of the second parameter
	 * @param <P2> the type of the third parameter
	 */
	interface FuncArity3<R, P0, P1, P2> {
		R func(P0 arg0, P1 arg1, P2 arg2);
	}

	/**
	 * An interface for methods of 4 arguments
	 *
	 * @param <R> the return type of the method
	 * @param <P0> the type of the first parameter
	 * @param <P1> the type of the second parameter
	 * @param <P2> the type of the third parameter
	 * @param <P3> the type of the fourth parameter
	 */
	interface FuncArity4<R, P0, P1, P2, P3> {
		R func(P0 arg0, P1 arg1, P2 arg2, P3 arg3);
	}

	/**
	 * Obtain a type specifier for the result of an asynchronous method
	 * 
	 * This is a shortcut for asynchronous methods whose implementations return a completable future
	 * from {@link AsyncUtils#sequence(TypeSpec)}, especially when the result is a complicated type.
	 * To work, the referenced method, usually the containing method, must return an implementation
	 * of {@link Future}. For example:
	 * 
	 * <pre>
	 * public CompletableFuture<Map<String, Set<Integer>>> computeNamedSets() {
	 * 	return sequence(TypeSpec.future(this::computeNamedSets)).then((seq) -> {
	 * 		// Do computation
	 * 	}).asCompletableFuture();
	 * }
	 * </pre>
	 * 
	 * This causes the sequence to have the correct type such that
	 * {@link AsyncSequenceWithoutTemp#finish()} returns a future having type compatible with the
	 * return type of the function. The referred method may take up to four parameters. Depending on
	 * optimizations applied by the JVM, this shortcut costs one instantiation of a method reference
	 * that is never used.
	 * 
	 * @param func the method returning a {@link Future}
	 * @return the specifier
	 */
	public static <U> TypeSpec<U> future(FuncArity0<? extends Future<U>> func) {
		return auto();
	}

	/**
	 * Obtain a type specifier for the result of an asynchronous method
	 * 
	 * @see #future(FuncArity0)
	 * @param func the method returning a {@link Future}
	 * @return the specifier
	 */
	public static <U, P0> TypeSpec<U> future(FuncArity1<? extends Future<U>, P0> func) {
		return auto();
	}

	/**
	 * Obtain a type specifier for the result of an asynchronous method
	 * 
	 * @see #future(FuncArity0)
	 * @param func the method returning a {@link Future}
	 * @return the specifier
	 */
	public static <U, P0, P1> TypeSpec<U> future(FuncArity2<? extends Future<U>, P0, P1> func) {
		return auto();
	}

	/**
	 * Obtain a type specifier for the result of an asynchronous method
	 * 
	 * @see #future(FuncArity0)
	 * @param func the method returning a {@link Future}
	 * @return the specifier
	 */
	public static <U, P0, P1, P2> TypeSpec<U> future(
			FuncArity3<? extends Future<U>, P0, P1, P2> func) {
		return auto();
	}

	/**
	 * Obtain a type specifier for the result of an asynchronous method
	 * 
	 * @see #future(FuncArity0)
	 * @param func the method returning a {@link Future}
	 * @return the specifier
	 */
	public static <U, P0, P1, P2, P3> TypeSpec<U> future(
			FuncArity4<? extends Future<U>, P0, P1, P2, P3> func) {
		return auto();
	}
}
