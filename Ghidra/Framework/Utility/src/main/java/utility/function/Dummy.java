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
package utility.function;

import java.util.function.*;

/**
 * A utility class to help create dummy stub functional interfaces
 */
public class Dummy {

	/**
	 * Creates a dummy callback
	 * @return a dummy callback
	 */
	public static Callback callback() {
		return () -> {
			// no-op
		};
	}

	/**
	 * Creates a dummy consumer
	 * @return a dummy consumer
	 */
	public static <T> Consumer<T> consumer() {
		return t -> {
			// no-op
		};
	}

	/**
	 * Creates a dummy function
	 * @param <T> the input type
	 * @param <R> the result type
	 * @return the function
	 */
	public static <T, R> Function<T, R> function() {
		return t -> null;
	}

	/**
	 * Creates a dummy supplier
	 * @param <T> the result type
	 * @return the supplier
	 */
	public static <T> Supplier<T> supplier() {
		return () -> null;
	}

	/**
	 * Creates a dummy runnable
	 * @return the runnable
	 */
	public static Runnable runnable() {
		return () -> {
			// no-op
		};
	}

	/**
	 * Returns the given consumer object if it is not {@code null}.  Otherwise, a {@link #consumer()}
	 * is returned.  This is useful to avoid using {@code null}.
	 *
	 * @param c the consumer function to check for {@code null}
	 * @return a non-null consumer
	 */
	public static <T> Consumer<T> ifNull(Consumer<T> c) {
		return c == null ? consumer() : c;
	}

	/**
	 * Returns the given callback object if it is not {@code null}.  Otherwise, a {@link #callback()}
	 * is returned.  This is useful to avoid using {@code null}.
	 *
	 * @param c the callback function to check for {@code null}
	 * @return a non-null callback function
	 */
	public static Callback ifNull(Callback c) {
		return c == null ? callback() : c;
	}

	/**
	 * Returns the given function object if it is not {@code null}.  Otherwise, a
	 * {@link #function()} is returned.  This is useful to avoid using {@code null}.
	 *
	 * @param <T> the input type
	 * @param <R> the result type
	 * @param f the function to check for {@code null}
	 * @return a non-null function
	 */
	public static <T, R> Function<T, R> ifNull(Function<T, R> f) {
		return f == null ? function() : f;
	}

	/**
	 * Returns the given callback object if it is not {@code null}.  Otherwise, a {@link #callback()}
	 * is returned.  This is useful to avoid using {@code null}.
	 *
	 * @param s the supplier function to check for {@code null}
	 * @return a non-null supplier
	 */
	public static <T> Supplier<T> ifNull(Supplier<T> s) {
		return s == null ? supplier() : s;
	}

	/**
	 * Returns the given runnable object if it is not {@code null}.  Otherwise, a {@link #runnable()}
	 * is returned.  This is useful to avoid using {@code null}.
	 *
	 * @param r the runnable function to check for {@code null}
	 * @return a non-null runnable
	 */
	public static Runnable ifNull(Runnable r) {
		return r == null ? runnable() : r;
	}
}
