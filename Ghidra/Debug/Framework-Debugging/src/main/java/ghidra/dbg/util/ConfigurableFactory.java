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
package ghidra.dbg.util;

import java.lang.annotation.*;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Supplier;

import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.util.Msg;

public interface ConfigurableFactory<T> {
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.TYPE)
	public @interface FactoryDescription {
		String brief();

		String htmlDetails();
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.FIELD)
	public @interface FactoryOption {
		/**
		 * The text to display next to the option
		 * 
		 * @return
		 */
		String value();
	}

	public interface Property<T> {
		Class<T> getValueClass();

		T getValue();

		void setValue(T value);

		boolean isEnabled();

		void setEnabled(boolean enabled);

		static <T> Property<T> fromAccessors(Class<T> cls, Supplier<T> getter, Consumer<T> setter) {
			return new Property<T>() {
				boolean enabled = true;

				@Override
				public Class<T> getValueClass() {
					return cls;
				}

				@Override
				public T getValue() {
					return getter.get();
				}

				@Override
				public void setValue(T value) {
					setter.accept(value);
				}

				@Override
				public boolean isEnabled() {
					return enabled;
				}

				@Override
				public void setEnabled(boolean enabled) {
					this.enabled = enabled;
				}
			};
		}
	}

	/**
	 * Build the object
	 * 
	 * Note, if the object requires some initialization, esp., if that such methods are not exposed
	 * via {@code T}, then this method should invoke them. Preferably, the returned future should
	 * not complete until initialization is complete.
	 * 
	 * @return a future which completes with the built and initialized object.
	 */
	CompletableFuture<? extends T> build();

	default String getBrief() {
		FactoryDescription annot = getClass().getAnnotation(FactoryDescription.class);
		if (annot == null) {
			return "Class: " + getClass().getSimpleName();
		}
		return annot.brief();
	}

	default String getHtmlDetails() {
		FactoryDescription annot = getClass().getAnnotation(FactoryDescription.class);
		if (annot == null) {
			return "Un-described factory: " + getClass().getName();
		}
		return annot.htmlDetails();
	}

	default Map<String, Property<?>> getOptions() {
		Map<String, Property<?>> result = new LinkedHashMap<>();
		for (Field f : getClass().getFields()) {
			FactoryOption annot = f.getAnnotation(FactoryOption.class);
			if (annot == null) {
				continue;
			}
			try {
				result.put(annot.value(), (Property<?>) f.get(this));
			}
			catch (Throwable e) {
				Msg.error(this, "Could not process option: " + f.getName(), e);
			}
		}
		return result;
	}

	default void writeConfigState(SaveState saveState) {
		for (Entry<String, Property<?>> opt : getOptions().entrySet()) {
			Property<?> property = opt.getValue();
			@SuppressWarnings({ "unchecked", "rawtypes" })
			ConfigFieldCodec<Object> codec = (ConfigFieldCodec) ConfigStateField
					.getCodecByType(property.getValueClass());
			if (codec == null) {
				continue;
			}
			codec.write(saveState, opt.getKey(), property.getValue());
		}
	}

	default void readConfigState(SaveState saveState) {
		for (Entry<String, Property<?>> opt : getOptions().entrySet()) {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			Property<Object> property = (Property) opt.getValue();
			ConfigFieldCodec<?> codec = ConfigStateField
					.getCodecByType(property.getValueClass());
			if (codec == null) {
				continue;
			}
			Object read = codec.read(saveState, opt.getKey(), null);
			if (read != null) {
				property.setValue(read);
			}
		}
	}
}
