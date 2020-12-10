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
package ghidra.framework.plugintool.util;

import java.lang.reflect.*;
import java.util.*;

import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.util.Msg;

public class AutoServiceListener<R> implements ServiceListener {
	protected static final Map<Class<?>, Set<ServiceSetter<?, ?>>> SETTERS_BY_RECEIVER_CLASS =
		new HashMap<>();
	protected static final Map<Class<?>, ReceiverProfile<?>> PROFILES_BY_RECEIVER_CLASS =
		new HashMap<>();

	protected interface ServiceSetter<R, S> {
		public void set(R receiver, S service);

		public Class<S> getServiceIface();
	}

	protected static class FieldServiceSetter<R, S> implements ServiceSetter<R, S> {
		protected final Field field;
		protected final Class<S> iface;

		@SuppressWarnings("unchecked")
		public FieldServiceSetter(Field field) {
			this.field = field;
			this.iface = (Class<S>) field.getType();

			field.setAccessible(true);
		}

		@Override
		public void set(R receiver, S service) {
			try {
				field.set(receiver, service);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public Class<S> getServiceIface() {
			return iface;
		}
	}

	protected static class MethodServiceSetter<R, S> implements ServiceSetter<R, S> {
		protected final Method method;
		protected final Class<S> iface;

		@SuppressWarnings("unchecked")
		public MethodServiceSetter(Method method) {
			this.method = method;
			Class<?>[] types = method.getParameterTypes();
			if (types.length != 1) {
				throw new IllegalArgumentException(
					"Service receiver method may take only one parameter");
			}
			this.iface = (Class<S>) types[0];

			method.setAccessible(true);
		}

		@Override
		public void set(R receiver, S service) {
			try {
				method.invoke(receiver, service);
			}
			catch (IllegalAccessException | IllegalArgumentException e) {
				throw new AssertionError(e);
			}
			catch (InvocationTargetException e) {
				Throwable cause = e.getCause();
				if (cause instanceof RuntimeException) {
					throw (RuntimeException) cause;
				}
				throw new AssertionError(e);
			}
		}

		@Override
		public Class<S> getServiceIface() {
			return iface;
		}
	}

	protected static class ReceiverProfile<R> {
		protected final Map<Class<?>, Set<ServiceSetter<R, ?>>> settersByService = new HashMap<>();

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public ReceiverProfile(Class<R> receiverCls) {
			for (ServiceSetter<?, ?> setter : collectSettersByReceiver(receiverCls)) {
				Class<?> iface = setter.getServiceIface();
				Set<ServiceSetter<R, ?>> settersForReceiver =
					settersByService.computeIfAbsent(iface, i -> new HashSet<>());
				settersForReceiver.add((ServiceSetter) setter);
			}
		}

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public <S> void serviceAdded(Class<S> iface, S service, R receiver) {
			Set<ServiceSetter<R, S>> settersForService = (Set) settersByService.get(iface);
			if (settersForService == null) {
				return; // Receiver does not consume this service
			}
			for (ServiceSetter<R, S> setter : settersForService) {
				setter.set(receiver, service);
			}
		}

		public void serviceRemoved(Class<?> iface, R receiver) {
			Set<ServiceSetter<R, ?>> settersForService = settersByService.get(iface);
			if (settersForService == null) {
				return; // Receiver does not consume this service
			}
			for (ServiceSetter<R, ?> setter : settersForService) {
				setter.set(receiver, null);
			}
		}

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public void notifyCurrentServices(PluginTool tool, R receiver) {
			for (Class<?> iface : settersByService.keySet()) {
				Object service = tool.getService(iface);
				if (service == null) {
					continue; // Service not yet provided
				}
				serviceAdded((Class) iface, service, receiver);
			}
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected static <R> Set<ServiceSetter<R, ?>> collectSettersByReceiver(Class<R> cls) {
		synchronized (SETTERS_BY_RECEIVER_CLASS) {
			if (SETTERS_BY_RECEIVER_CLASS.containsKey(cls)) {
				return (Set) SETTERS_BY_RECEIVER_CLASS.get(cls);
			}

			Set<ServiceSetter<?, ?>> result = new HashSet<>();
			SETTERS_BY_RECEIVER_CLASS.put(cls, result);

			Class<?> superclass = cls.getSuperclass();
			if (superclass != null) {
				Set<ServiceSetter<?, ?>> superResult = (Set) collectSettersByReceiver(superclass);
				result.addAll(superResult);
			}

			for (Class<?> superiface : cls.getInterfaces()) {
				Set<ServiceSetter<?, ?>> superResult = (Set) collectSettersByReceiver(superiface);
				result.addAll(superResult);
			}

			for (Field f : cls.getDeclaredFields()) {
				AutoServiceConsumed annotation = f.getAnnotation(AutoServiceConsumed.class);
				if (annotation == null) {
					continue;
				}
				try {
					result.add(new FieldServiceSetter(f));
				}
				catch (IllegalArgumentException e) {
					Msg.error(AutoServiceListener.class, e.getMessage());
				}
			}

			for (Method m : cls.getDeclaredMethods()) {
				AutoServiceConsumed annotation = m.getAnnotation(AutoServiceConsumed.class);
				if (annotation == null) {
					continue;
				}
				try {
					result.add(new MethodServiceSetter(m));
				}
				catch (IllegalArgumentException e) {
					Msg.error(AutoServiceListener.class, e.getMessage());
				}
			}

			return (Set) result;
		}
	}

	protected final R receiver;
	protected final ReceiverProfile<R> profile;

	@SuppressWarnings("unchecked")
	public AutoServiceListener(R receiver) {
		this.receiver = receiver;
		this.profile = (ReceiverProfile<R>) PROFILES_BY_RECEIVER_CLASS
			.computeIfAbsent(receiver.getClass(), ReceiverProfile::new);
	}

	@Override
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void serviceAdded(Class<?> iface, Object service) {
		profile.serviceAdded((Class) iface, service, receiver);
	}

	@Override
	public void serviceRemoved(Class<?> iface, Object service) {
		profile.serviceRemoved(iface, receiver);
	}

	public void notifyCurrentServices(PluginTool tool) {
		profile.notifyCurrentServices(tool, receiver);
	}
}
