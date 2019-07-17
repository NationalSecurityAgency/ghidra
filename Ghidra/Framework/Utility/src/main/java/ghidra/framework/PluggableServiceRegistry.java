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
package ghidra.framework;

import java.util.HashMap;
import java.util.Map;

public class PluggableServiceRegistry {

	private static Map<Class<?>, Object> MAP = new HashMap<Class<?>, Object>();

	public static <T> void registerPluggableService(Class<? extends T> pluggableServiceClass,
			T replacementInstance) throws PluggableServiceRegistryException {
		if (!MAP.containsKey(pluggableServiceClass)) {
			// no entry yet, just put it in
			MAP.put(pluggableServiceClass, replacementInstance);
			return;
		}

		Object registeredInstance = MAP.get(pluggableServiceClass);
		Class<? extends Object> alreadyRegisteredClass = registeredInstance.getClass();
		Class<? extends Object> replacementClass = replacementInstance.getClass();
		if (alreadyRegisteredClass.isAssignableFrom(replacementClass)) {
			// we're making the service more specific
			MAP.put(pluggableServiceClass, replacementInstance);
			return;
		}

		if (replacementClass.isAssignableFrom(alreadyRegisteredClass)) {
			// we're trying to be more generic; silently drop it
			return;
		}

		throw new PluggableServiceRegistryException(pluggableServiceClass, alreadyRegisteredClass,
			replacementClass);
	}

	@SuppressWarnings("unchecked")
	// We checked the type when we put it in the map
	public static <T> T getPluggableService(Class<? extends T> pluggableServiceClass) {
		return (T) MAP.get(pluggableServiceClass);
	}
}
