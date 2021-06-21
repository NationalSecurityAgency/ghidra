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
package generic;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;

public interface TupleRecord<T extends TupleRecord<T>> {
	List<Function<T, ?>> getFieldAccessors();

	@SuppressWarnings("unchecked")
	default boolean doEquals(Object that) {
		if (!this.getClass().equals(that.getClass())) {
			return false;
		}
		for (Function<T, ?> field : getFieldAccessors()) {
			if (!Objects.equals(field.apply((T) this), field.apply((T) that))) {
				return false;
			}
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	default int doHashCode() {
		int hash = 1;
		for (Function<T, ?> field : getFieldAccessors()) {
			hash *= 31;
			Object val = field.apply((T) this);
			if (val == null) {
				continue;
			}
			hash += val.hashCode();
		}
		return hash;
	}
}
