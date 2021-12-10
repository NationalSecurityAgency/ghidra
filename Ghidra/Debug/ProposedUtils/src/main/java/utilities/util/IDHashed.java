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
package utilities.util;

public class IDHashed<T> {
	public final T obj;

	public IDHashed(T obj) {
		this.obj = obj;
	}

	@Override
	public String toString() {
		return obj.toString();
	}

	@Override
	public int hashCode() {
		return System.identityHashCode(obj);
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof IDHashed<?>)) {
			return false;
		}
		IDHashed<?> that = (IDHashed<?>) o;
		return this.obj.equals(that.obj);
	}
}
