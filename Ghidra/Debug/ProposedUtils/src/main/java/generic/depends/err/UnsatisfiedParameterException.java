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
package generic.depends.err;

import java.util.Collections;
import java.util.Set;

public class UnsatisfiedParameterException extends Exception {
	private final Set<Class<?>> left;

	public UnsatisfiedParameterException(Set<Class<?>> left) {
		super("Could not resolve required parameter for next in: " + left +
			". Note: it may be a circular dependency.");
		this.left = Collections.unmodifiableSet(left);
	}

	public Set<Class<?>> getLeft() {
		return left;
	}
}
