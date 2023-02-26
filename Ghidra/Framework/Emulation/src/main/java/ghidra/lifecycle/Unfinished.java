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
package ghidra.lifecycle;

/**
 * This serves both as a marker interface for classes missing important methods and as container for
 * the {@link #TODO(String, Object...))} method.
 * 
 * <p>
 * TODO: It'd be nice to optionally ignore TODO exceptions, but this seems to require a dependency
 * on JUnit, which is a no-no within {@code src/main}. Maybe there's a way via the abstract test
 * case, or an interface mixin....
 */
public interface Unfinished {
	public class TODOException extends UnsupportedOperationException {
		public TODOException(String message) {
			super(message);
		}

		public TODOException() {
			this("TODO");
		}
	}

	/**
	 * Perhaps a little better than returning {@code null} or throwing
	 * {@link UnsupportedOperationException} yourself, as references can be found in most IDEs.
	 * 
	 * @param message A message describing the task that is yet to be done
	 * @param ignore variables involved in the implementation so far
	 */
	static <T> T TODO(String message, Object... ignore) {
		throw new TODOException(message);
	}

	/**
	 * Perhaps a little better than returning {@code null} or throwing
	 * {@link UnsupportedOperationException} yourself, as references can be found in most IDEs.
	 */
	static <T> T TODO() {
		throw new TODOException();
	}
}
