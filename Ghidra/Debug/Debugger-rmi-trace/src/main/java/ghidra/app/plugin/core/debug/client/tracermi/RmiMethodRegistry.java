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
package ghidra.app.plugin.core.debug.client.tracermi;

import java.lang.annotation.*;
import java.util.HashMap;
import java.util.Map;

public class RmiMethodRegistry {

	/**
	 * An annotation for marking remote methods.
	 */
	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface TraceMethod {
		String action() default "";

		String display() default "";

		String description() default "";
	}

	Map<String, RmiRemoteMethod> map = new HashMap<>();

	public RmiRemoteMethod getMethod(String key) {
		return map.get(key);
	}

	public void putMethod(String key, RmiRemoteMethod value) {
		map.put(key, value);
	}

	public Map<String, RmiRemoteMethod> getMap() {
		return map;
	}

}
