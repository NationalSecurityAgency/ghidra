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

import org.apache.commons.lang3.StringUtils;

import generic.theme.GColor;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public interface AutoOptions {

	record CategoryAndName(String category, String name) implements Comparable<CategoryAndName> {

		protected static String getPluginPackageName(Plugin plugin) {
			return plugin.getPluginDescription().getPluginPackage().getName();
		}

		private static String computeCategory(String[] categoryNames, Plugin plugin) {
			return categoryNames.length == 0
					? getPluginPackageName(plugin)
					: computeName(categoryNames);
		}

		private static String computeName(String[] names) {
			return String.join(".", names);
		}

		public CategoryAndName(AutoOptionDefined annotation, Plugin plugin) {
			this(computeCategory(annotation.category(), plugin), computeName(annotation.name()));
		}

		public CategoryAndName(AutoOptionConsumed annotation, Plugin plugin) {
			// Same code because annotations cannot extend one another
			this(computeCategory(annotation.category(), plugin), computeName(annotation.name()));
		}

		@Override
		public int compareTo(CategoryAndName that) {
			int cmp;
			cmp = this.category.compareTo(that.category);
			if (cmp != 0) {
				return cmp;
			}
			cmp = this.name.compareTo(that.name);
			if (cmp != 0) {
				return cmp;
			}
			return 0;
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
			ToolOptions options = plugin.getTool().getOptions(key.category);
			if (options.isRegistered(key.name)) {
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

			if (defaultValue instanceof GColor gColor) {
				options.registerThemeColorBinding(key.name, gColor.getId(), help, description);
			}
			/*
			else if ( is font option ) {
			
				// Note: there is no font value to check against for fonts in the new Theme system.
				// If annotation fonts are needed, then they should be bound by String id.  Likely, 
				// annotation fonts are not needed now that have themes.  We also probably no 
				// longer need annotation colors either. 
			
				options.registerThemeFontBinding(description, fontId, help, description);
			}
			*/
			else {
				options.registerOption(key.name, type, defaultValue, help, description,
					editor);
				// TODO: Wish Ghidra would do this upon any option registration
				options.putObject(key.name, defaultValue, type);
			}

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
