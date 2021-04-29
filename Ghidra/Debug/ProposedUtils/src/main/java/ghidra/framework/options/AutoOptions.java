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

import java.beans.PropertyEditor;
import java.lang.annotation.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.function.Function;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.ImmutableList;

import generic.ComparableTupleRecord;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public interface AutoOptions {

	static class CategoryAndName implements ComparableTupleRecord<CategoryAndName> {
		public static final List<Function<CategoryAndName, ? extends Comparable<?>>> ACCESSORS =
			ImmutableList.of(CategoryAndName::getCategory, CategoryAndName::getName);

		private final String category;
		private final String name;

		protected static String getPluginPackageName(Plugin plugin) {
			return plugin.getPluginDescription().getPluginPackage().getName();
		}

		public CategoryAndName(AutoOptionDefined annotation, Plugin plugin) {
			String[] categoryNames = annotation.category();
			if (categoryNames.length == 0) {
				this.category = getPluginPackageName(plugin);
			}
			else {
				this.category = StringUtils.join(categoryNames, ".");
			}
			this.name = StringUtils.join(annotation.name(), ".");
		}

		public CategoryAndName(AutoOptionConsumed annotation, Plugin plugin) {
			// Same code because annotations cannot extend one another
			String[] categoryNames = annotation.category();
			if (categoryNames.length == 0) {
				this.category = getPluginPackageName(plugin);
			}
			else {
				this.category = StringUtils.join(categoryNames, ".");
			}
			this.name = StringUtils.join(annotation.name(), ".");
		}

		public CategoryAndName(String category, String name) {
			this.category = category;
			this.name = name;
		}

		@Override
		public List<Function<CategoryAndName, ? extends Comparable<?>>> getComparableFieldAccessors() {
			return ACCESSORS;
		}

		public String getCategory() {
			return category;
		}

		public String getName() {
			return name;
		}

		@Override
		public int hashCode() {
			return doHashCode();
		}

		@Override
		public boolean equals(Object obj) {
			return doEquals(obj);
		}

		@Override
		public String toString() {
			return category + ":" + name;
		}
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@interface OldValue {
		// no attributes
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@interface NewValue {
		// no attributes
	}

	public interface Wiring {
		void dispose();
	}

	public static class WiringImpl implements Wiring {
		@SuppressWarnings("unused") // strong reference
		private AutoOptionsListener<?> listener;

		public WiringImpl(AutoOptionsListener<?> listener) {
			this.listener = listener;
		}

		@Override
		public void dispose() {
			this.listener = null;
		}
	}

	public static Wiring wireOptions(Plugin plugin) {
		return wireOptions(plugin, plugin);
	}

	public static Wiring wireOptions(Plugin plugin, Object receiver) {
		registerOptionsDefined(plugin, receiver.getClass(), receiver);
		return wireOptionsConsumed(plugin, receiver);
	}

	static void registerOptionsDefined(Plugin plugin, Class<?> cls, Object receiver) {
		Class<?> superclass = cls.getSuperclass();
		if (superclass != null) {
			registerOptionsDefined(plugin, superclass, receiver);
		}
		for (Field f : cls.getDeclaredFields()) {
			AutoOptionDefined annotation = f.getAnnotation(AutoOptionDefined.class);
			if (annotation == null) {
				continue;
			}
			CategoryAndName key = new CategoryAndName(annotation, plugin);
			ToolOptions options = plugin.getTool().getOptions(key.getCategory());
			if (options.isRegistered(key.getName())) {
				continue;
			}
			f.setAccessible(true);
			HelpLocation help = getHelpLocation(plugin.getName(), annotation.help());
			Object defaultValue;
			try {
				defaultValue = f.get(receiver);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertionError(e);
			}
			OptionType type = annotation.type();
			if (type == OptionType.NO_TYPE) {
				type = OptionType.getOptionType(defaultValue);
				// TODO: OptionType does have getValueClass, if searching by class is better
			}
			if (type == OptionType.NO_TYPE) {
				throw new IllegalArgumentException(
					"Could not determine option type from default value: " + f + " = " +
						defaultValue);
			}
			String description = annotation.description();
			Class<? extends PropertyEditor> editorClass = annotation.editor();
			final PropertyEditor editor;
			if (editorClass == PropertyEditor.class) {
				editor = null;
			}
			else {
				try {
					editor = editorClass.getConstructor().newInstance();
				}
				catch (InstantiationException | IllegalAccessException | IllegalArgumentException
						| InvocationTargetException | NoSuchMethodException | SecurityException e) {
					throw new IllegalArgumentException(
						"editor class must have accessible default constructor", e);
				}
			}
			options.registerOption(key.getName(), type, defaultValue, help, description, editor);
			// TODO: Wish Ghidra would do this upon any option registration
			options.putObject(key.getName(), defaultValue, type);
		}
	}

	public static HelpLocation getHelpLocation(String defaultTopic, HelpInfo annot) {
		if (annot.topic().length == 0) {
			return null;
		}
		String anchor = annot.anchor();
		if ("".equals(anchor)) {
			anchor = null;
		}
		String topic =
			annot.topic().length == 0 ? defaultTopic : StringUtils.join(annot.topic(), ".");
		return new HelpLocation(topic, anchor);
	}

	public static Wiring wireOptionsConsumed(Plugin plugin, Object receiver) {
		PluginTool tool = plugin.getTool();
		AutoOptionsListener<?> listener = new AutoOptionsListener<>(plugin, receiver);
		for (String category : listener.getCategories()) {
			ToolOptions options = tool.getOptions(category);
			options.addOptionsChangeListener(listener);
		}
		listener.notifyCurrentValues(tool);
		return new WiringImpl(listener);
	}
}
