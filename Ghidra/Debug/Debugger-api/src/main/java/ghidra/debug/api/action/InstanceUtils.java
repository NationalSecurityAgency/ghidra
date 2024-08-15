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
package ghidra.debug.api.action;

import java.util.Map;
import java.util.function.Function;

import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

public class InstanceUtils {
	public static <T> void collectUniqueInstances(Class<T> cls, Map<String, T> map,
			Function<T, String> keyFunc) {
		// This is wasteful. Existing instances will be re-instantiated and thrown away
		for (T t : ClassSearcher.getInstances(cls)) {
			String key = keyFunc.apply(t);
			T exists = map.get(key);
			if (exists != null) {
				if (exists.getClass().equals(t.getClass())) {
					continue;
				}
				Msg.error(LocationTrackingSpec.class,
					cls.getSimpleName() + " conflict over key: " + key);
			}
			map.put(key, t);
		}
	}
}
