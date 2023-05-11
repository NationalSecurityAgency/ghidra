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
package ghidra.app.util.template;

import ghidra.GhidraOptions;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;

/**
 * Class for simplify names with template data. This class can be used with tool options or
 * as a stand alone configurable simplifier.
 */
public class TemplateSimplifier {
	public static final String SUB_OPTION_NAME = "Templates";

	public static final String SIMPLIFY_TEMPLATES_OPTION =
		SUB_OPTION_NAME + ".Simplify Templated Names";
	public static final String TEMPLATE_NESTING_DEPTH_OPTION =
		SUB_OPTION_NAME + ".Max Template Depth";
	public static final String MAX_TEMPLATE_LENGTH_OPTION =
		SUB_OPTION_NAME + ".Max Template Length";
	public static final String MIN_TEMPLATE_LENGTH_OPTION =
		SUB_OPTION_NAME + ".Min Template Length";

	public static final String SIMPLY_TEMPLATES_DESCRIPTION =
		"Determines whether to diplay templated names in a simplified form.";
	public static final String TEMPLATE_NESTING_DEPTH_DESCRIPTION =
		"Maximum template depth to display when simplify templated names.";
	public static final String MAX_TEMPLATE_LENGTH_DESCRIPTION =
		"Maximum number of characters to display in a template before truncating the name in the middle.";
	public static final String MIN_TEMPLATE_LENGTH_DESCRIPTION =
		"Minumum size of template to be simplified";

	private boolean doSimplify = true;
	private int templateNestingDepth = 0;
	private int maxTemplateLength = 20;
	private int minTemplateLength = 10;

	/**
	 * Constructor to use for a TemplateSimplifier that doesn't use values from ToolOptions
	 */
	public TemplateSimplifier() {
		// constructs using standard simplifying options.
	}

	/**
	 * Constructor to use for a TemplateSimplifier that operates using the current values in 
	 * the tool options
	 * @param fieldOptions the "Listing Field" options
	 */
	public TemplateSimplifier(ToolOptions fieldOptions) {
		checkForCorrectOptions(fieldOptions);
		ensureRegistered(fieldOptions);
		loadOptions(fieldOptions);

	}

	/**
	 * Sets the template nesting depth to be simplified. A depth of 0 simplifies the entire 
	 * template portion of the name (everything in between {@code <>}). A depth of 1 leaves one 
	 * level of template information
	 * @param depth the nesting depth
	 */
	public void setNestingDepth(int depth) {
		this.templateNestingDepth = depth;
	}

	/**
	 * Returns the nesting depth for simplification
	 * @return the nesting depth for simplification
	 */
	public int getNestingDepth() {
		return templateNestingDepth;
	}

	/**
	 * Sets the maximum length do display the template portion. If, after any nesting,
	 * simplification, the resulting template string is longer that the max length, the middle
	 * portion will be replaced with "..." to reduce the template string to the given max length.
	 * @param maxLength the max length of a template to display
	 */
	public void setMaxTemplateLength(int maxLength) {
		this.maxTemplateLength = maxLength;
	}

	/**
	 * Gets the maximum length that a template will display.
	 * @return the maximum length that a template will display
	 */
	public int getMaxTemplateLength() {
		return maxTemplateLength;
	}

	/**
	 * Sets if this TemplateSimplifier is enabled. If disabled, the {@link #simplify(String)} 
	 * method will return the input string.
	 * @param doSimplify true to do simplification, false to do nothing
	 */
	public void setEnabled(boolean doSimplify) {
		this.doSimplify = doSimplify;
	}

	/**
	 * Returns if this TemplateSimplifier is enabled.
	 * @return if this TemplateSimplifier is enabled
	 */
	public boolean isEnabled() {
		return doSimplify;
	}

	/**
	 * Sets the minimum length for a template string to be simplified. In other words, template
	 * strings less than this length will not be changed.
	 * @param minLength the minimum length to simplify
	 */
	public void setMinimumTemplateLength(int minLength) {
		this.minTemplateLength = minLength;
	}

	/**
	 * Returns the minimum length of a template string that will be simplified.
	 * @return the minimum length of a template string that will be simplified.
	 */
	public int getMinimumTemplateLength() {
		return minTemplateLength;
	}

	/**
	 * Simplifies any template string in the given input base on the current simplification
	 * settings.
	 * @param input the input string to be simplified
	 * @return a simplified string
	 */
	public String simplify(String input) {
		if (!doSimplify) {
			return input;
		}
		return doSimplify(input, templateNestingDepth);
	}

	/**
	 * Reloads the current simplification settings from the given field options
	 * @param fieldOptions the options to retrieve the simplification settings.
	 */
	public void reloadFromOptions(ToolOptions fieldOptions) {
		checkForCorrectOptions(fieldOptions);
		loadOptions(fieldOptions);
	}

	/**
	 * Notification that options have changed
	 * @param options the options object that has changed values
	 * @param optionName the name of the options that changed
	 * @param oldValue the old value for the option that changed
	 * @param newValue the new value for the option that changed
	 * @return true if the option that changed was a template simplification option
	 */
	public boolean fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(SIMPLIFY_TEMPLATES_OPTION)) {
			doSimplify = (Boolean) newValue;
			return true;
		}
		if (optionName.equals(TEMPLATE_NESTING_DEPTH_OPTION)) {
			templateNestingDepth = (Integer) newValue;
			return true;
		}
		if (optionName.equals(MAX_TEMPLATE_LENGTH_OPTION)) {
			maxTemplateLength = (Integer) newValue;
			return true;
		}
		if (optionName.equals(MIN_TEMPLATE_LENGTH_OPTION)) {
			minTemplateLength = (Integer) newValue;
			return true;
		}

		return false;
	}

	private String doSimplify(String input, int depth) {
		StringBuilder builder = new StringBuilder();
		int pos = 0;
		TemplateString ts;
		while ((ts = findTemplateString(input, pos)) != null) {
			builder.append(input.substring(pos, ts.start));
			String template = ts.getTemplate();
			if (depth == 0) {
				builder.append("<");
				if (template.length() <= minTemplateLength) {
					builder.append(template);
				}
				builder.append(">");
			}
			else {
				builder.append("<");
				String simplifiedTemplate = doSimplify(template, depth - 1);
				if (simplifiedTemplate.length() > maxTemplateLength) {
					simplifiedTemplate = middleTruncate(template);
				}
				builder.append(simplifiedTemplate);
				builder.append(">");
			}
			pos = ts.end + 1;
		}
		builder.append(input.substring(pos));
		return builder.toString();
	}

	private String middleTruncate(String input) {
		int partSize = maxTemplateLength / 2;
		return input.substring(0, partSize) + "..." + input.substring(input.length() - partSize);
	}

	private static TemplateString findTemplateString(String input, int pos) {
		for (int i = pos; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c == '<') {
				int end = findMatchingEnd(input, i + 1);
				if (end > i) {
					return new TemplateString(input, i, end);
				}
			}
		}
		return null;
	}

	private static int findMatchingEnd(String input, int start) {
		int depth = 0;
		for (int i = start; i < input.length(); i++) {
			char c = input.charAt(i);
			if (c == '>') {
				if (depth == 0) {
					return i;
				}
				depth--;
			}
			else if (c == '<') {
				depth++;
			}
		}
		return -1;
	}

	private record TemplateString(String input, int start, int end) {
		String getTemplate() {
			return input.substring(start + 1, end);	// don't include the enclosing <> chars
		}
	}

	private void loadOptions(ToolOptions options) {
		doSimplify = options.getBoolean(SIMPLIFY_TEMPLATES_OPTION, doSimplify);
		templateNestingDepth = options.getInt(TEMPLATE_NESTING_DEPTH_OPTION, templateNestingDepth);
		maxTemplateLength = options.getInt(MAX_TEMPLATE_LENGTH_OPTION, maxTemplateLength);
		minTemplateLength = options.getInt(MIN_TEMPLATE_LENGTH_OPTION, minTemplateLength);
	}

	private void checkForCorrectOptions(ToolOptions fieldOptions) {
		if (!GhidraOptions.CATEGORY_BROWSER_FIELDS.equals(fieldOptions.getName())) {
			throw new IllegalArgumentException(
				"Expected options named \"" + GhidraOptions.CATEGORY_BROWSER_FIELDS + "\", not \"" +
					fieldOptions.getName() + "\"");
		}
	}

	private void ensureRegistered(Options options) {
		if (options.isRegistered(SIMPLIFY_TEMPLATES_OPTION)) {
			return;
		}

		HelpLocation help = new HelpLocation("CodeBrowserPlugin", "Template Display Options");

		options.getOptions(SUB_OPTION_NAME).setOptionsHelpLocation(help);

		options.registerOption(SIMPLIFY_TEMPLATES_OPTION, doSimplify, help,
			SIMPLY_TEMPLATES_DESCRIPTION);

		options.registerOption(TEMPLATE_NESTING_DEPTH_OPTION, templateNestingDepth, help,
			TEMPLATE_NESTING_DEPTH_DESCRIPTION);

		options.registerOption(MAX_TEMPLATE_LENGTH_OPTION, maxTemplateLength, help,
			MAX_TEMPLATE_LENGTH_DESCRIPTION);

		options.registerOption(MIN_TEMPLATE_LENGTH_OPTION, minTemplateLength, help,
			MIN_TEMPLATE_LENGTH_DESCRIPTION);
	}
}
