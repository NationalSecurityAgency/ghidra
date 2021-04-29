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
package ghidra.dbg.util;

import java.util.LinkedHashMap;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;

/**
 * A means of dynamically binding method calls to one of many registered handlers by sub-type
 *
 * A handler is a method accepting a sub-type and a custom argument. The handler can be assigned to
 * handle any sub-type of its first argument. When the {@link #handle(Object, Object)} method of
 * this map is called, it invokes the mapped handler, or throws {@link IllegalArgumentException} if
 * there is not a handler for the given object type. The passed type must exactly match the type of
 * the registered handler. This abstraction is a useful replacement for {@code instanceof} checks in
 * an {@code if-else-if} series.
 *
 * @param <T> the root type for all handlers and passed objects
 * @param <A> the type of custom additional argument
 * @param <R> the type of result returned by the handler
 */
public class HandlerMap<T, A, R> {
	private LinkedHashMap<Class<? extends T>, BiFunction<?, ? super A, ? extends R>> map =
		new LinkedHashMap<>();

	/**
	 * Add a handler to the map
	 * 
	 * @param cls the type assigned to this handler
	 * @param handler the handler
	 * @return the previous handler, if any, otherwise {@code null}
	 */
	@SuppressWarnings("unchecked")
	public <U extends T> BiFunction<? super U, ? super A, ? extends R> put(Class<U> cls,
			BiFunction<? super U, ? super A, ? extends R> handler) {
		return (BiFunction<? super U, ? super A, ? extends R>) map.put(cls, handler);
	}

	/**
	 * Add a void handler to the map
	 * 
	 * Note that this wraps the {@link BiConsumer} in a {@link BiFunction}. If the handler is
	 * replaced, the {@link BiFunction} is returned instead of the {@link BiConsumer}.
	 * 
	 * @param cls the type assigned to this handler
	 * @param handler the handler
	 * @return the previous handler, if any, otherwise {@code null}
	 */
	public <U extends T> BiFunction<? super U, ? super A, ? extends R> putVoid(Class<U> cls,
			BiConsumer<? super U, ? super A> handler) {
		return put(cls, (u, a) -> {
			handler.accept(u, a);
			return null;
		});
	}

	/**
	 * Invoke the a handler for the given object
	 * 
	 * The given object's type is reflected to determine the appropriate handler to call. The
	 * object's type must exactly match one of the handlers' assigned types. Being a subclass of an
	 * assigned type does not constitute a match. The type and the custom argument are then passed
	 * to the handler. If there is no match, an {@link IllegalArgumentException} is thrown.
	 * 
	 * @param t the object to handle
	 * @param a the custom additional argument, often {@code null}
	 * @return a future
	 * @throws IllegalArgumentException if no handler is assigned to the given object's type
	 */
	public R handle(T t, A a) {
		@SuppressWarnings("unchecked")
		BiFunction<T, A, ? extends R> function =
			(BiFunction<T, A, ? extends R>) map.get(t.getClass());
		if (function != null) {
			//Msg.debug(this, "Handling: " + t);
			return function.apply(t, a);
		}
		throw new IllegalArgumentException("No handler for " + t);
	}
}
