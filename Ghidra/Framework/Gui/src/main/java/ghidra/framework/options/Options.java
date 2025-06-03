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

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyEditor;
import java.io.File;
import java.util.*;
import java.util.function.Supplier;

import javax.swing.KeyStroke;

import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

public interface Options {
	public static final char DELIMITER = '.';
	public final static String DELIMITER_STRING = new String(new char[] { DELIMITER });
	public final static String ILLEGAL_DELIMITER = DELIMITER_STRING + DELIMITER_STRING;

	/**
	 * Get the name of this options object.
	 *
	 * @return String
	 */
	public String getName();

	/**
	 * Returns a unique id for option in this options with the given name.  This will be the full
	 * path name to the root options object.
	 * @param optionName the name of the option for which to get an ID;
	 * @return the unique ID for the given option.
	 */
	public String getID(String optionName);

	/**
	 * Returns the OptionType of the given option.
	 * @param optionName the name of the option for which to get the type.
	 * @return the OptionType of option with the given name.
	 */
	public OptionType getType(String optionName);

	/**
	 * Get the property editor for the option with the given name. Note: This method must be called
	 * from the swing thread.
	 * @param optionName the option name
	 * @return either the PropertyEditor that was registered for this option or a default editor
	 * for the property type if one can be found; otherwise null.
	 * @throws IllegalStateException if not called from the swing thread.
	 */
	public PropertyEditor getPropertyEditor(String optionName);

	/**
	 * Get the property editor that was registered for the specific option with the given name.  Unlike
	 * the getPropertyEditor() method, this method does not have to be called from the swing thread
	 * @param optionName the option name
	 * @return the PropertyEditor that was registered for this option.
	 */

	public PropertyEditor getRegisteredPropertyEditor(String optionName);

	/**
	 * Returns a list of Options objects that are nested one level down from this Options object.
	 * @return  a list of Options objects that are nested one level down from this Options object.
	 */
	public List<Options> getChildOptions();

	/**
	 * Returns a list of option names that immediately fall under this options.  For example, if this options
	 * object had the following options named ("a", "b", "c.d"), only "a" and "b" would be returned.  The
	 * "c.d" leaf option name could be returned by getOptions("c").getLeafOptionNames()
	 * @return the list of the names of the options that are immediate children of this options object.
	 */
	public List<String> getLeafOptionNames();

	/**
	 * Set the location for where help can be found for this entire options object.
	 * @param helpLocation location for help on the option
	 */
	public void setOptionsHelpLocation(HelpLocation helpLocation);

	/**
	 * Returns the HelpLocation for this entire Options object.
	 * @return  the HelpLocation for this entire Options object.
	 */
	public HelpLocation getOptionsHelpLocation();

	/**
	 * Get the location for where help can be found for the option with
	 * the given name.
	 * @param optionName name of the option
	 * @return null if the help location was not set on the option
	 */
	public HelpLocation getHelpLocation(String optionName);

	/**
	 * Registers an option with a description, help location, and a default value without specifying
	 * the option type.  This form requires that the default value not be null so that the option
	 * type can be inferred from the default value.
	 * <P>
	 * Note, this method should not be used for
	 * colors and font as doing so will result in those colors and fonts becoming disconnected
	 * to the current theme. Instead use
	 *
	 * {@link #registerThemeColorBinding(String, String, HelpLocation, String)} or
	 * {@link #registerThemeFontBinding(String, String, HelpLocation, String)}.
	 * @param optionName the name of the option being registered.
	 * @param defaultValue the defaultValue for the option. The default value must not be
	 * null so that the OptionType can be determined.  If the default value should be null, use
	 * {@link #registerOption(String, OptionType, Object, HelpLocation, String)}
	 * @param help the HelpLocation for this option.
	 * @param description a description of the option.
	 * @throws IllegalArgumentException if the defaultValue is null
	 */
	public void registerOption(String optionName, Object defaultValue, HelpLocation help,
			String description);

	/**
	 * Registers an option with a description, help location, and a optional default value.  With an optional
	 * default value, an OptionType must be passed as it is otherwise derived from the default value.
	 * <P>
	 * Note, this method should not be used for
	 * colors and font as doing so will result in those colors and fonts becoming disconnected
	 * to the current theme. Instead use
	 * {@link #registerThemeColorBinding(String, String, HelpLocation, String)} or
	 * {@link #registerThemeFontBinding(String, String, HelpLocation, String)}.
	 *
	 * @param optionName the name of the option being registered.
	 * @param type the OptionType for this options.
	 * @param defaultValue the defaultValue for the option. In this version of the method, the default
	 * value may be null.
	 * @param help the HelpLocation for this option.
	 * @param description a description of the option.
	 */
	public void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description);

	/**
	 * Registers an option with a description, help location, and a optional default value.  With an optional
	 * default value, an OptionType must be passed as it is otherwise derived from the default value.
	 * <P>
	 * Note, this method should not be used for
	 * colors and font as doing so will result in those colors and fonts becoming disconnected
	 * to the current theme. Instead use
	 * {@link #registerThemeColorBinding(String, String, HelpLocation, String)} or
	 * {@link #registerThemeFontBinding(String, String, HelpLocation, String)}.
	 * <P>
	 * Note 1: we use a <i>supplier</i> of a custom editor, instead of a custom editor, to avoid
	 * creating {@link PropertyEditor}s until needed.  This allows us to use the same API in both
	 * GUI mode and headless mode.  If GUI property editors are created in headless mode, exceptions
	 * may be thrown.  This API will not use the supplier when in headless mode, this avoiding the
	 * creation of GUI components.  For this to work correctly, clients using custom property
	 * editors must defer construction of the editor until the supplier is called.
	 * <P>
	 * Note 2: most clients are calling this API on the Swing thread, but that is not a requirement.
	 * Any clients calling this method not on the Swing thread that also have a custom property 
	 * editor, need to ensure they create that editor on the Swing thread (this is a Java 
	 * requirement).
	 *
	 * @param optionName the name of the option being registered.
	 * @param type the OptionType for this options.
	 * @param defaultValue the defaultValue for the option. In this version of the method, the default
	 * value may be null.
	 * @param help the HelpLocation for this option.
	 * @param description a description of the option.
	 * @param editor an optional supplier of a custom editor for this property. Note if the option
	 * is a custom option, then the property editor can't be null;
	 * @throws IllegalStateException if the options is a custom option and the editor is null.
	 */
	public void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description, Supplier<PropertyEditor> editor);

	/**
	 * Use instead
	 * {@link #registerOption(String, OptionType, Object, HelpLocation, String, Supplier)}
	 * @param optionName the name of the option being registered.
	 * @param type the OptionType for this options.
	 * @param defaultValue the defaultValue for the option. In this version of the method, the default
	 * value may be null.
	 * @param help the HelpLocation for this option.
	 * @param description a description of the option.
	 * @param editor an optional supplier of a custom editor for this property. Note if the option
	 * is a custom option, then the property editor can't be null;
	 * @deprecated Use instead
	 * {@link #registerOption(String, OptionType, Object, HelpLocation, String, Supplier)}
	 */
	@Deprecated(since = "11.0.2", forRemoval = true)
	default public void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description, PropertyEditor editor) {
		String caller = ReflectionUtilities.getClassNameOlderThan(Options.class);
		String message = """
				Using deprecated call to registerOption(PropertyEditor) from % for option %s
				""".formatted(caller, optionName);
		Msg.debug(this, message);
		registerOption(optionName, type, defaultValue, help, description, () -> editor);
	}

	/**
	 * Register/binds the option to a theme color id. Changing the option's color via the options
	 * Gui will result in directly changing the theme color of the given color id.
	 * @param optionName the name of the color option
	 * @param colorId the theme color id whose color value is changed when the option's color is changed
	 * @param help the HelpLocation for this option
	 * @param description a description of the option
	 */
	public void registerThemeColorBinding(String optionName, String colorId, HelpLocation help,
			String description);

	/**
	 * Register/binds the option to a theme font id. Changing the option's font via the options
	 * Gui will result in directly changing the theme color of the given font id.
	 * @param optionName the name of the font option
	 * @param fontId the theme color id whose color value is changed when the option's color
	 * is changed
	 * @param help the HelpLocation for this option
	 * @param description a description of the option
	 */
	public void registerThemeFontBinding(String optionName, String fontId, HelpLocation help,
			String description);

	/**
	 * Register the options editor that will handle the editing for all the options or a sub-group
	 * of options.
	 * <P>
	 * Note: we use a <i>supplier</i> of a custom editor, instead of a custom editor, to avoid
	 * creating {@link PropertyEditor}s until needed.  This allows us to use the same API in both
	 * GUI mode and headless mode.  If GUI property editors are created in headless mode, exceptions
	 * may be thrown.  This API will not use the supplier when in headless mode, this avoiding the
	 * creation of GUI components.  For this to work correctly, clients using custom property
	 * editors must defer construction of the editor until the supplier is called.
	 * @param editor a supplier for the custom editor panel to be used to edit the options or
	 * sub-group of options.
	 */
	public void registerOptionsEditor(Supplier<OptionsEditor> editor);

	/**
	 * Use instead {@link #registerOptionsEditor(Supplier)}
	 * @param editor the editor
	 * @deprecated Use instead {@link #registerOptionsEditor(Supplier)}
	 */
	@Deprecated(since = "11.0.2", forRemoval = true)
	default public void registerOptionsEditor(OptionsEditor editor) {
		String caller = ReflectionUtilities.getClassNameOlderThan(Options.class);
		String message = """
				Using deprecated call to registerOption(OptionsEditor) from % for options %s
				""".formatted(caller, getName());
		Msg.debug(this, message);
		registerOptionsEditor(() -> editor);
	}

	/**
	 * Get the editor that will handle editing all the values in this options or sub group of options.
	 * @return null if no options editor was registered
	 */
	public OptionsEditor getOptionsEditor();

	/**
	 * Put the object value.  If the option exists, the type must match the type of the existing
	 * object.
	 * @param optionName the option name
	 * @param obj the option value
	 * @throws IllegalStateException if the object does not match the existing type of the option.
	 * @throws IllegalArgumentException if the object is null or not a supported type.
	 */
	public void putObject(String optionName, Object obj);

	/**
	 * Get the object value; called when the options dialog is being
	 * populated.
	 * @param optionName option name
	 * @param defaultValue default value
	 * @return object with the given option name; if no option was found,
	 * return default value (this value is not stored in the option maps)
	 */
	public Object getObject(String optionName, Object defaultValue);

	/**
	 * Get the boolean value for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there
	 * is no option with the given name.
	 * @return boolean option value
	 */
	public boolean getBoolean(String optionName, boolean defaultValue);

	/**
	 * Get the byte array for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there
	 * is no option with the given name
	 * @return byte[] byte array value
	 */
	public byte[] getByteArray(String optionName, byte[] defaultValue);

	/**
	 * Get the int value for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there
	 * is no option with the given name
	 * @return int option value
	 */
	public int getInt(String optionName, int defaultValue);

	/**
	 * Get the double value for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there
	 * is no option with the given name
	 * @return double value for the option
	 */
	public double getDouble(String optionName, double defaultValue);

	/**
	 * Get the float value for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there
	 * is no option with the given name
	 * @return float value for the option
	 */
	public float getFloat(String optionName, float defaultValue);

	/**
	 * Get the long value for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there
	 * is no option with the given name
	 * @return long value for the option
	 */
	public long getLong(String optionName, long defaultValue);

	/**
	 * Get the custom option value for the given option name.
	 * @param optionName option name
	 * @param defaultValue  value that is stored and returned if there
	 * is no option with the given name
	 * @return WrappedOption value for the option
	 */
	public CustomOption getCustomOption(String optionName, CustomOption defaultValue);

	/**
	 * Get the Color for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there is no
	 * option with the given name
	 * @return Color option
	 * @throws IllegalArgumentException is a option exists with the given
	 * name but it is not a Color
	 */
	public Color getColor(String optionName, Color defaultValue);

	/**
	 * Get the File for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there is no
	 * option with the given name
	 * @return File option
	 * @throws IllegalArgumentException is a option exists with the given
	 * name but it is not a File options
	 */
	public File getFile(String optionName, File defaultValue);

	/**
	 * Get the Date for the given option name.
	 * @param pName the property name
	 * @param date the default date that is stored and returned if there is no
	 * option with the given name
	 * @return the Date for the option
	 * @throws IllegalArgumentException is a option exists with the given
	 * name but it is not a Date options
	 */
	public Date getDate(String pName, Date date);

	/**
	 * Get the Font for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there is no
	 * option with the given name
	 * @return Font option
	 * @throws IllegalArgumentException is a option exists with the given
	 * name but it is not a Font
	 */
	public Font getFont(String optionName, Font defaultValue);

	/**
	 * Get the KeyStroke for the given action name.
	 * @param optionName the option name
	 * @param defaultValue value that is stored and returned if there is no
	 * option with the given name
	 * @return KeyStroke option
	 * @throws IllegalArgumentException is a option exists with the given
	 * name but it is not a KeyStroke
	 * @deprecated use {@link #getActionTrigger(String, ActionTrigger)} instead
	 */
	@Deprecated(since = "11.1", forRemoval = true)
	public KeyStroke getKeyStroke(String optionName, KeyStroke defaultValue);

	/**
	 * Get the {@link ActionTrigger} for the given full action name.
	 * @param optionName the action name
	 * @param defaultValue value that is stored and returned if there is no
	 * option with the given name
	 * @return the action trigger
	 */
	public ActionTrigger getActionTrigger(String optionName, ActionTrigger defaultValue);

	/**
	 * Get the string value for the given option name.
	 * @param optionName option name
	 * @param defaultValue value that is stored and returned if there is no
	 * option with the given name
	 * @return String value for the option
	 */
	public String getString(String optionName, String defaultValue);

	/**
	 * Get the Enum value for the given option name.
	 * @param optionName option name
	 * @param defaultValue default value that is stored and returned if there is
	 * no option with the given name
	 * @return Enum value for the option
	 */
	public <T extends Enum<T>> T getEnum(String optionName, T defaultValue);

	/**
	 * Sets the long value for the option.
	 * @param optionName name of the option
	 * @param value value of the option
	 */
	public void setLong(String optionName, long value);

	/**
	 * Sets the boolean value for the option.
	 * @param optionName name of the option
	 * @param value value of the option
	 */
	public void setBoolean(String optionName, boolean value);

	/**
	 * Sets the int value for the option.
	 * @param optionName name of the option
	 * @param value value of the option
	 */
	public void setInt(String optionName, int value);

	/**
	 * Sets the double value for the option.
	 * @param optionName name of the option
	 * @param value value of the option
	 */
	public void setDouble(String optionName, double value);

	/**
	 * Sets the float value for the option.
	 * @param optionName name of the option
	 * @param value value of the option
	 */
	public void setFloat(String optionName, float value);

	/**
	 * Sets the Custom option value for the option.
	 * @param optionName name of the option
	 * @param value the value
	 */
	public void setCustomOption(String optionName, CustomOption value);

	/**
	 * Sets the byte[] value for the given option name.
	 * @param optionName the name of the option on which to save bytes.
	 * @param value the value
	 */
	public void setByteArray(String optionName, byte[] value);

	/**
	 * Sets the File value for the option.
	 * @param optionName name of the option
	 * @param value the value
	 */
	public void setFile(String optionName, File value);

	/**
	 * Sets the Date value for the option.
	 * @param optionName name of the option
	 * @param newSetting the Date to set
	 */
	public void setDate(String optionName, Date newSetting);

	/**
	 * Sets the Color value for the option
	 * @param optionName name of the option
	 * @param value Color to set
	 * @throws IllegalArgumentException if a option with the given
	 * name already exists, but it is not a Color
	 */
	public void setColor(String optionName, Color value);

	/**
	 * Sets the Font value for the option
	 * @param optionName name of the option
	 * @param value Font to set
	 * @throws IllegalArgumentException if a option with the given
	 * name already exists, but it is not a Font
	 */
	public void setFont(String optionName, Font value);

	/**
	 * Sets the KeyStroke value for the option
	 * @param optionName name of the option
	 * @param value KeyStroke to set
	 * @throws IllegalArgumentException if a option with the given
	 * name already exists, but it is not a KeyStroke
	 * @deprecated use {@link #setActionTrigger(String, ActionTrigger)} instead
	 */
	@Deprecated(since = "11.1", forRemoval = true)
	public void setKeyStroke(String optionName, KeyStroke value);

	/**
	 * Sets the action trigger value for the option
	 * @param optionName name of the option
	 * @param value action trigger to set
	 * @throws IllegalArgumentException if a option with the given
	 * name already exists, but it is not an action trigger
	 */
	public void setActionTrigger(String optionName, ActionTrigger value);

	/**
	 * Set the String value for the option.
	 * @param optionName name of the option
	 * @param value value of the option
	 */
	public void setString(String optionName, String value);

	/**
	 * Set the Enum value for the option.
	 * @param optionName name of the option
	 * @param value Enum value of the option
	 */
	public <T extends Enum<T>> void setEnum(String optionName, T value);

	/**
	 * Remove the option name.
	 * @param optionName name of option to remove
	 */
	public void removeOption(String optionName);

	/**
	 * Get the list of option names. This method will return the names (paths) of all options contained
	 * in this options object or below.  For example, if the options has ("aaa", "bbb", "ccc.ddd"),
	 * all three will be returned.  the {@link Options#getLeafOptionNames()} method will return only
	 * the "aaa" and "bbb" names.
	 * @return the list of all option names(paths) under this options.
	 */
	public List<String> getOptionNames();

	/**
	 * Return true if a option exists with the given name.
	 * @param optionName option name
	 * @return true if there exists an option with the given name
	 */
	public boolean contains(String optionName);

	/**
	 * Get the description for the given option name.
	 * @param optionName name of the option
	 * @return null if the description or option name does not exist
	 */
	public String getDescription(String optionName);

	/**
	 * Returns true if the specified option has been registered.  Only registered names
	 * are saved.
	 * @param optionName the option name
	 * @return true if registered
	 */
	public boolean isRegistered(String optionName);

	/**
	 * Returns true if the option with the given name's current value is the default value.
	 * @param optionName the name of the option.
	 * @return true if the options has its current value equal to its default value.
	 */
	public boolean isDefaultValue(String optionName);

	/**
	 * Restores <b>all</b> options contained herein to their default values.
	 *
	 * @see #restoreDefaultValue(String)
	 */
	public void restoreDefaultValues();

	/**
	 * Restores the option denoted by the given name to its default value.
	 *
	 * @param optionName The name of the option to restore
	 * @see #restoreDefaultValues()
	 */
	public void restoreDefaultValue(String optionName);

	/**
	 * Returns a Options object that is a sub-options of this options.
	 *
	 * <p>Note: the option path can have {@link Options#DELIMITER} characters which will be
	 * used to create a hierarchy with each element in the path resulting in sub-option of the
	 * previous path element.
	 *
	 * @param path the path for the sub-options object
	 * @return an Options object that is a sub-options of this options
	 */
	public Options getOptions(String path);

	/**
	 * Create an alias in this options for an existing option in some other options object.
	 * @param aliasName the name within this options object that will actually refer to some other
	 * options object.
	 * @param options the options object that has the actual option.
	 * @param optionsName the name within the given options object of the actual option.
	 */
	public void createAlias(String aliasName, Options options, String optionsName);

	/**
	 * Returns
	 * @param aliasName the name of the alias.
	 * @return  a Options object that is a sub-options of this options.
	 */
	public boolean isAlias(String aliasName);

	/**
	 * Returns the default value for the given option.
	 * @param optionName the name of the option for which to retrieve the default value.
	 * @return  the default value for the given option.
	 */
	public Object getDefaultValue(String optionName);

	/**
	 * Returns the value as a string for the given option.
	 * @param name the name of the option for which to retrieve the value as a string
	 * @return  the value as a string for the given option.
	 */
	public String getValueAsString(String name);

	/**
	 * Returns the default value as a string for the given option.
	 * @param optionName the name of the option for which to retrieve the default value as a string
	 * @return  the default value as a string for the given option.
	 */
	public String getDefaultValueAsString(String optionName);

	/**
	 * Returns true if the two options objects have the same set of options and values
	 * @param options1 the first options object to test
	 * @param options2 the second options object to test
	 * @return true if the two options objects have the same set of options and values
	 */
	public static boolean hasSameOptionsAndValues(Options options1, Options options2) {
		List<String> leafOptionNames1 = options1.getOptionNames();
		List<String> leafOptionNames2 = options2.getOptionNames();
		Collections.sort(leafOptionNames1);
		Collections.sort(leafOptionNames2);

		if (!leafOptionNames1.equals(leafOptionNames2)) {
			return false;
		}
		for (String optionName : leafOptionNames1) {
			Object value1 = options1.getObject(optionName, null);
			Object value2 = options2.getObject(optionName, null);
			if (!Objects.equals(value1, value2)) {
				return false;
			}
		}
		return true;

	}
}
