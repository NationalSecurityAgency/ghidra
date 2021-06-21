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
package ghidra.framework.plugintool;

import java.lang.reflect.Field;

import ghidra.framework.plugintool.annotation.AutoServiceProvided;
import ghidra.framework.plugintool.util.AutoServiceListener;
import ghidra.util.Msg;

public interface AutoService {
	public interface Wiring {
		void dispose();
	}

	static class WiringImpl implements Wiring {
		@SuppressWarnings("unused") // strong reference
		private AutoServiceListener<?> listener;

		public WiringImpl(AutoServiceListener<?> listener) {
			this.listener = listener;
		}

		@Override
		public void dispose() {
			this.listener = null;
		}
	}

	public static Wiring wireServicesProvidedAndConsumed(Plugin plugin) {
		registerServicesProvided(plugin, plugin.getClass(), plugin);
		return wireServicesConsumed(plugin, plugin);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	static void registerServicesProvided(Plugin plugin, Class<?> cls, Object provider) {
		Class<?> superclass = cls.getSuperclass();
		if (superclass != null) {
			registerServicesProvided(plugin, superclass, provider);
		}
		for (Field f : cls.getDeclaredFields()) {
			AutoServiceProvided annotation = f.getAnnotation(AutoServiceProvided.class);
			if (annotation == null) {
				continue;
			}
			Class<?> iface = annotation.iface();
			Class<?> type = f.getType();
			if (!iface.isAssignableFrom(type)) {
				Msg.error(AutoService.class,
					type + " does not implement service interface " + iface);
				continue;
			}
			boolean wasAccessible = f.isAccessible();
			f.setAccessible(true);
			try {
				plugin.registerServiceProvided((Class) iface, f.get(provider));
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
			f.setAccessible(wasAccessible);
		}
	}

	public static Wiring wireServicesConsumed(Plugin plugin, Object receiver) {
		// TODO: Validate against PluginInfo?

		AutoServiceListener<Object> listener = new AutoServiceListener<>(receiver);
		PluginTool tool = plugin.getTool();
		tool.addServiceListener(listener);
		listener.notifyCurrentServices(tool);

		return new WiringImpl(listener);
	}
}
