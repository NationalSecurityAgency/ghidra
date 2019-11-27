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

/**
 * A generic functional interface that allows you to consume an item and potentially throw
 * an exception.  
 * 
 * @param <T> the input type 
 * @param <E> the exception of your choice
 */
@FunctionalInterface
public interface ExceptionalConsumer<T, E extends Exception> {

	/**
	 * The method that will be called
	 * 
	 * @param t the input
	 * @throws E if the call throws an exception
	 */
	public void accept(T t) throws E;
}
