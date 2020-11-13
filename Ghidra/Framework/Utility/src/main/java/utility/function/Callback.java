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
 * A generic functional interface that is more semantically sound than {@link Runnable}.  Use
 * anywhere you wish to have a generic callback function.
 */
@FunctionalInterface
public interface Callback {

	/**
	 * Creates a dummy callback function.  This is useful to avoid using <code>null</code>.
	 * @return a dummy callback function
	 */
	public static Callback dummy() {
		return () -> {
			// no-op
		};
	}

	/**
	 * Returns the given callback object if it is not <code>null</code>.  Otherwise, a {@link #dummy()} 
	 * callback is returned.  This is useful to avoid using <code>null</code>.
	 * 
	 * @param c the callback function to check for <code>null</code>
	 * @return a non-null callback function
	 */
	public static Callback dummyIfNull(Callback c) {
		if (c == null) {
			return dummy();
		}
		return c;
	}

	/**
	 * The method that will be called.
	 */
	public void call();
}
