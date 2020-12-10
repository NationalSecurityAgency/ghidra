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
package ghidra.framework.options;

import java.lang.reflect.*;
import java.util.*;
import java.util.function.BiFunction;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.options.*;
import ghidra.framework.options.AutoOptions.*;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.framework.options.annotation.AutoOptionDefined;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

public class AutoOptionsListener<R> implements OptionsChangeListener {
	protected static final Map<Class<?>, Set<OptionSetter<?>>> SETTERS_BY_RECEIVER_CLASS =
		new HashMap<>();
	protected static final Map<Class<?>, ReceiverProfile<?>> PROFILES_BY_RECEIVER_CLASS =
		new HashMap<>();

	protected interface OptionSetter<R> {
		public void set(R receiver, Object newValue, Object oldValue);

		public CategoryAndName getKey();
	}

	protected static class FieldOptionSetter<R> implements OptionSetter<R> {
		protected final Field field;
		protected final CategoryAndName key;

		public FieldOptionSetter(Field field, AutoOptionDefined annotation, Plugin plugin) {
			this(field, new CategoryAndName(annotation, plugin));
		}

		public FieldOptionSetter(Field field, AutoOptionConsumed annotation, Plugin plugin) {
			this(field, new CategoryAndName(annotation, plugin));
		}

		public FieldOptionSetter(Field field, String category, String name) {
			this(field, new CategoryAndName(category, name));
		}

		public FieldOptionSetter(Field field, CategoryAndName key) {
			this.field = field;
			this.key = key;

			field.setAccessible(true);
		}

		@Override
		public void set(R receiver, Object newValue, /* unused */ Object oldValue) {
			try {
				field.set(receiver, newValue);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(
					"Could not set " + field + " = " + newValue + " for option " + key, e);
			}
		}

		@Override
		public CategoryAndName getKey() {
			return key;
		}
	}

	protected enum ParamOrder {
		NONE((o, n) -> new Object[] {}),
		NEW_ONLY((o, n) -> new Object[] { n }),
		OLD_ONLY((o, n) -> new Object[] { o }),
		NEW_OLD((o, n) -> new Object[] { n, o }),
		OLD_NEW((o, n) -> new Object[] { o, n });

		private final BiFunction<Object, Object, Object[]> pop;

		ParamOrder(BiFunction<Object, Object, Object[]> pop) {
			this.pop = pop;
		}

		public Object[] populate(Object oldVal, Object newVal) {
			return this.pop.apply(oldVal, newVal);
		}
	}

	protected static class MethodOptionSetter<R> implements OptionSetter<R> {
		protected final Method method;
		protected final CategoryAndName key;
		protected final ParamOrder order;

		public MethodOptionSetter(Method method, AutoOptionConsumed annotation, Plugin plugin) {
			this(method, new CategoryAndName(annotation, plugin));
		}

		public MethodOptionSetter(Method method, String category, String name) {
			this(method, new CategoryAndName(category, name));
		}

		public MethodOptionSetter(Method method, CategoryAndName key) {
			this.method = method;
			this.key = key;

			method.setAccessible(true);

			Parameter[] parameters = method.getParameters();
			if (parameters.length == 0) {
				this.order = ParamOrder.NONE;
			}
			else if (parameters.length == 1) {
				if (parameters[0].getAnnotation(OldValue.class) != null) {
					this.order = ParamOrder.OLD_ONLY;
				}
				else {
					this.order = ParamOrder.NEW_ONLY;
				}
			}
			else if (parameters.length == 2) {
				if (parameters[0].getAnnotation(NewValue.class) != null) {
					if (parameters[1].getAnnotation(NewValue.class) != null) {
						throw new IllegalArgumentException("Cannot apply " +
							NewValue.class.getName() + " to both parameters of " + method);
					}
					this.order = ParamOrder.NEW_OLD;
				}
				else if (parameters[0].getAnnotation(OldValue.class) != null) {
					if (parameters[1].getAnnotation(OldValue.class) != null) {
						throw new IllegalArgumentException("Cannot apply " +
							OldValue.class.getName() + " to both parameters of " + method);
					}
					this.order = ParamOrder.OLD_NEW;
				}
				else {
					if (parameters[1].getAnnotation(NewValue.class) != null) {
						this.order = ParamOrder.OLD_NEW;
					}
					else {
						this.order = ParamOrder.NEW_OLD;
					}
				}
			}
			else {
				throw new IllegalArgumentException(AutoOptionConsumed.class + "-annotated method " +
					method + " cannot have more than two parameters");
			}
		}

		@Override
		public void set(R receiver, Object newValue, Object oldValue) {
			Object[] args = order.populate(oldValue, newValue);
			try {
				method.invoke(receiver, args);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				String argsStr = StringUtils.join(args, ",");
				// Don't throw, so other consumers get updated
				Msg.error(this,
					"Could not invoke " + method + "(" + argsStr + ") for option " + key, e);
			}
			catch (InvocationTargetException e) {
				Throwable cause = e.getCause();
				if (cause instanceof RuntimeException) {
					throw (RuntimeException) cause;
				}
				String argsStr = StringUtils.join(args, ",");
				// Don't throw, so other consumers get updated
				Msg.error(this,
					"Error during invocation of " + method + "(" + argsStr + ") for option " + key,
					e.getCause());
			}
		}

		@Override
		public CategoryAndName getKey() {
			return key;
		}
	}

	protected static class ReceiverProfile<R> {
		protected final Map<CategoryAndName, Set<OptionSetter<R>>> settersByOption =
			new HashMap<>();

		protected final Set<String> categories = new HashSet<>();
		protected final Set<String> categoriesView = Collections.unmodifiableSet(categories);

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public ReceiverProfile(Class<R> receiverCls, Plugin plugin) {
			for (OptionSetter<?> setter : collectSettersByReceiver(receiverCls, plugin)) {
				CategoryAndName key = setter.getKey();
				Set<OptionSetter<R>> settersForReceiver =
					settersByOption.computeIfAbsent(key, k -> new HashSet<>());
				settersForReceiver.add((OptionSetter) setter);
				categories.add(key.getCategory());
			}
		}

		public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
				Object newValue, R receiver) {
			if (oldValue == null) {
				// TODO: Wish Ghidra would give default as old value, in case null was actual value
				// Maybe Ghidra does not allow null?
				oldValue = options.getDefaultValue(optionName);
			}
			CategoryAndName key = new CategoryAndName(options.getName(), optionName);
			Set<OptionSetter<R>> settersForOption = settersByOption.get(key);
			if (settersForOption == null) {
				return; // Receiver does not consume this option
			}
			for (OptionSetter<R> setter : settersForOption) {
				setter.set(receiver, newValue, oldValue);
			}
		}

		public void notifyCurrentValues(PluginTool tool, R receiver) {
			for (Map.Entry<CategoryAndName, Set<OptionSetter<R>>> ent : settersByOption
				.entrySet()) {
				CategoryAndName key = ent.getKey();
				ToolOptions options = tool.getOptions(key.getCategory());
				Option opt = options.getOption(key.getName(), OptionType.NO_TYPE, null);
				if (!opt.isRegistered()) {
					continue;
				}
				Object newValue = opt.getValue(null);
				Object oldValue = opt.getDefaultValue();

				for (OptionSetter<R> setter : ent.getValue()) {
					setter.set(receiver, newValue, oldValue);
				}
			}
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected static <R> Set<OptionSetter<R>> collectSettersByReceiver(Class<R> cls,
			Plugin plugin) {
		synchronized (SETTERS_BY_RECEIVER_CLASS) {
			if (SETTERS_BY_RECEIVER_CLASS.containsKey(cls)) {
				return (Set) SETTERS_BY_RECEIVER_CLASS.get(cls);
			}

			Set<OptionSetter<?>> result = new HashSet<>();
			SETTERS_BY_RECEIVER_CLASS.put(cls, result);

			Class<?> superclass = cls.getSuperclass();
			if (superclass != null) {
				Set<OptionSetter<?>> superResult =
					(Set) collectSettersByReceiver(superclass, plugin);
				result.addAll(superResult);
			}

			for (Class<?> superiface : cls.getInterfaces()) {
				Set<OptionSetter<?>> superResult =
					(Set) collectSettersByReceiver(superiface, plugin);
				result.addAll(superResult);
			}

			for (Field f : cls.getDeclaredFields()) {
				AutoOptionDefined defined = f.getAnnotation(AutoOptionDefined.class);
				if (defined != null) {
					try {
						result.add(new FieldOptionSetter(f, defined, plugin));
					}
					catch (IllegalArgumentException e) {
						Msg.error(AutoOptionsListener.class, e.getMessage());
					}
				}
				AutoOptionConsumed consumed = f.getAnnotation(AutoOptionConsumed.class);
				if (consumed != null) {
					try {
						// TODO: Validate type compatibility
						// Potential problem: consumed options may be registered yet
						result.add(new FieldOptionSetter(f, consumed, plugin));
					}
					catch (IllegalArgumentException e) {
						Msg.error(AutoOptionsListener.class, e.getMessage());
					}
				}
			}

			for (Method m : cls.getDeclaredMethods()) {
				AutoOptionConsumed consumed = m.getAnnotation(AutoOptionConsumed.class);
				if (consumed == null) {
					continue;
				}
				try {
					result.add(new MethodOptionSetter(m, consumed, plugin));
				}
				catch (IllegalArgumentException e) {
					Msg.error(AutoOptionsListener.class, e.getMessage());
				}
			}

			return (Set) result;
		}
	}

	protected final R receiver;
	protected final ReceiverProfile<R> profile;

	@SuppressWarnings("unchecked")
	public AutoOptionsListener(Plugin plugin, R receiver) {
		this.receiver = receiver;
		this.profile = (ReceiverProfile<R>) PROFILES_BY_RECEIVER_CLASS
			.computeIfAbsent(receiver.getClass(), cls -> new ReceiverProfile<>(cls, plugin));
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		profile.optionsChanged(options, optionName, oldValue, newValue, receiver);
	}

	public void notifyCurrentValues(PluginTool tool) {
		profile.notifyCurrentValues(tool, receiver);
	}

	public Set<String> getCategories() {
		return profile.categoriesView;
	}
}
