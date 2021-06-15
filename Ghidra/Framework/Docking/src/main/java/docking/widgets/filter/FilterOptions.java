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
package docking.widgets.filter;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.Icon;

import org.jdom.Element;

import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class FilterOptions {
	private static final Icon CONTAINS_ICON = ResourceManager.loadImage("images/page_code.png");
	private static final Icon STARTS_WITH_ICON = ResourceManager.loadImage("images/page_go.png");
	private static final Icon EXACT_MATCH_ICON = ResourceManager.loadImage("images/page_green.png");
	private static final Icon REG_EX_ICON = ResourceManager.loadImage("images/page_excel.png");
	private static final Icon NOT_ICON = ResourceManager.loadImage("images/bullet_delete.png");

	final static Map<Character, String> DELIMITER_NAME_MAP = new HashMap<>(20);

	// Any non-alphanumeric char can be used as a delimiter.
	static {
		DELIMITER_NAME_MAP.put(' ', "Space");
		DELIMITER_NAME_MAP.put('~', "Tilde");
		DELIMITER_NAME_MAP.put('`', "Back quote");
		DELIMITER_NAME_MAP.put('!', "Exclamation point");
		DELIMITER_NAME_MAP.put('@', "At sign");
		DELIMITER_NAME_MAP.put('#', "Pound sign");
		DELIMITER_NAME_MAP.put('$', "Dollar sign");
		DELIMITER_NAME_MAP.put('%', "Percent sign");
		DELIMITER_NAME_MAP.put('^', "Caret");
		DELIMITER_NAME_MAP.put('&', "Ampersand");
		DELIMITER_NAME_MAP.put('*', "Asterisk");
		DELIMITER_NAME_MAP.put('-', "Hyphen");
		DELIMITER_NAME_MAP.put('_', "Underscore");
		DELIMITER_NAME_MAP.put('+', "Plus sign");
		DELIMITER_NAME_MAP.put('=', "Equals sign");
		DELIMITER_NAME_MAP.put('|', "Pipe (Bar)");
		DELIMITER_NAME_MAP.put(':', "Colon");
		DELIMITER_NAME_MAP.put(';', "Semi-colon");
		DELIMITER_NAME_MAP.put(',', "Comma");
		DELIMITER_NAME_MAP.put('.', "Period (Dot)");
	}

	// @formatter:off
	public static final String VALID_MULTITERM_DELIMITERS =
		DELIMITER_NAME_MAP.keySet()
		.stream()
		.sorted()
		.map(c -> Character.toString(c))
		.collect(Collectors.joining(""));
	
	public static final String[] VALID_MULTITERM_DELIMITERS_ARRAY =
		DELIMITER_NAME_MAP.keySet()
		.stream()
		.sorted()
		.map(c -> Character.toString(c))
		.collect(Collectors.toList())
		.toArray(new String[DELIMITER_NAME_MAP.size()]);
	// @formatter:on

	public static final Character DEFAULT_DELIMITER = ',';

	private final boolean caseSensitive;
	private final boolean inverted;
	private final TextFilterStrategy textFilterStrategy;
	private final boolean allowGlobbing;
	private final boolean multiTerm;
	private final char delimitingCharacter;
	private final MultitermEvaluationMode evalMode;

	public FilterOptions() {
		this(TextFilterStrategy.CONTAINS, true, false, false);
	}

	public FilterOptions(TextFilterStrategy textFilterStrategy, boolean allowGlobbing,
			boolean caseSensitive, boolean inverted) {
		this(textFilterStrategy, allowGlobbing, caseSensitive, inverted, false, DEFAULT_DELIMITER,
			MultitermEvaluationMode.AND);
	}

	public FilterOptions(TextFilterStrategy textFilterStrategy, boolean allowGlobbing,
			boolean caseSensitive, boolean inverted, boolean multiTerm, char delimiterCharacter) {
		this(textFilterStrategy, allowGlobbing, caseSensitive, inverted, multiTerm,
			delimiterCharacter, MultitermEvaluationMode.AND);
	}

	public FilterOptions(TextFilterStrategy textFilterStrategy, boolean allowGlobbing,
			boolean caseSensitive, boolean inverted, boolean multiTerm, char delimiterCharacter,
			MultitermEvaluationMode mode) {
		if (textFilterStrategy == null) {
			throw new NullPointerException("TextFilterStrategy Cannot be null");
		}

		if (multiTerm && VALID_MULTITERM_DELIMITERS.indexOf(delimiterCharacter) < 0) {
			throw new IllegalArgumentException("Delimiter character '" + delimiterCharacter +
				"' not among '" + VALID_MULTITERM_DELIMITERS + "'");
		}

		this.textFilterStrategy = textFilterStrategy;
		this.allowGlobbing = allowGlobbing;
		this.caseSensitive = caseSensitive;
		this.inverted = inverted;

		this.multiTerm =
			textFilterStrategy == TextFilterStrategy.REGULAR_EXPRESSION ? false : multiTerm;
		this.delimitingCharacter = delimiterCharacter;
		this.evalMode = mode;
	}

	public static FilterOptions restoreFromXML(Element element) {

		String filtertypeName = element.getAttributeValue("FILTER_TYPE");
		TextFilterStrategy textFilterStrategy = getTextFilterStrategy(filtertypeName);
		String globValue = element.getAttributeValue("GLOBBING");
		boolean globbing = globValue == null ? true : Boolean.parseBoolean(globValue);
		boolean caseSensitive = Boolean.parseBoolean(element.getAttributeValue("CASE_SENSITIVE"));
		boolean inverted = Boolean.parseBoolean(element.getAttributeValue("INVERTED"));

		boolean multiterm = Boolean.parseBoolean(element.getAttributeValue("MULTITERM"));
		String delimiterCharacterStr = element.getAttributeValue("TERM_DELIMITER");
		if (delimiterCharacterStr == null) {
			delimiterCharacterStr = "" + DEFAULT_DELIMITER;
		}

		boolean andMode = Boolean.parseBoolean(element.getAttributeValue("AND_EVAL_MODE", "True"));

		return new FilterOptions(textFilterStrategy, globbing, caseSensitive, inverted, multiterm,
			delimiterCharacterStr.charAt(0),
			andMode ? MultitermEvaluationMode.AND : MultitermEvaluationMode.OR);
	}

	private static TextFilterStrategy getTextFilterStrategy(String filtertypeName) {
		if (filtertypeName == null) {
			return TextFilterStrategy.CONTAINS;
		}
		return TextFilterStrategy.valueOf(filtertypeName);

	}

	public Element toXML() {
		Element xmlElement = new Element("Filter_Options");
		xmlElement.setAttribute("FILTER_TYPE", textFilterStrategy.name());
		xmlElement.setAttribute("GLOBBING", Boolean.toString(allowGlobbing));
		xmlElement.setAttribute("CASE_SENSITIVE", Boolean.toString(caseSensitive));
		xmlElement.setAttribute("INVERTED", Boolean.toString(inverted));

		xmlElement.setAttribute("MULTITERM", Boolean.toString(multiTerm));
		xmlElement.setAttribute("TERM_DELIMITER", "" + delimitingCharacter);

		xmlElement.setAttribute("AND_EVAL_MODE",
			Boolean.toString(evalMode == MultitermEvaluationMode.AND));

		return xmlElement;
	}

	public boolean isCaseSensitive() {
		return caseSensitive;
	}

	public boolean isGlobbingAllowed() {
		return allowGlobbing;
	}

	public boolean isInverted() {
		return inverted;
	}

	public TextFilterStrategy getTextFilterStrategy() {
		return textFilterStrategy;
	}

	public boolean isMultiterm() {
		return multiTerm;
	}

	public char getDelimitingCharacter() {
		return delimitingCharacter;
	}

	public MultitermEvaluationMode getMultitermEvaluationMode() {
		return evalMode;
	}

	public TextFilterFactory getTextFilterFactory() {
		switch (textFilterStrategy) {
			case CONTAINS:
				return new ContainsTextFilterFactory(caseSensitive, allowGlobbing);
			case MATCHES_EXACTLY:
				return new MatchesExactlyTextFilterFactory(caseSensitive, allowGlobbing);
			case STARTS_WITH:
				return new StartsWithTextFilterFactory(caseSensitive, allowGlobbing);
			case REGULAR_EXPRESSION:
				return new RegularExpressionTextFilterFactory();
		}
		return null;
	}

	public TermSplitter getTermSplitter() {
		if (isMultiterm()) {
			return new CharacterTermSplitter(delimitingCharacter);
		}
		return null;
	}

	public static Icon getIcon(TextFilterStrategy filterStrategy) {
		switch (filterStrategy) {
			case CONTAINS:
				return CONTAINS_ICON;
			case MATCHES_EXACTLY:
				return EXACT_MATCH_ICON;
			case STARTS_WITH:
				return STARTS_WITH_ICON;
			case REGULAR_EXPRESSION:
				return REG_EX_ICON;
			default:
				return CONTAINS_ICON;
		}

	}

	public Icon getFilterStateIcon() {
		Icon icon = getIcon(textFilterStrategy);
		if (inverted) {
			int width = icon.getIconWidth();
			int height = icon.getIconHeight();
			int notWidth = NOT_ICON.getIconWidth();
			int notHeight = NOT_ICON.getIconHeight();
			icon = new MultiIcon(icon,
				new TranslateIcon(NOT_ICON, width - notWidth / 2, height - notHeight / 2));
		}
		return icon;
	}

	public String getFilterDescription() {
		StringBuffer buf = new StringBuffer("<html>");
		buf.append("<b>Filter Settings:</b>");
		buf.append("<br>");

		buf.append("<table>");

		buf.append("<tr>");
		buf.append("<td>");
		buf.append("&nbsp;");
		buf.append("&nbsp;");
		buf.append("Match Type: ");
		buf.append("</td>");

		buf.append("<td>");
		buf.append(textFilterStrategy.toString());
		buf.append("</td>");
		buf.append("</tr>");

		buf.append("<tr>");
		buf.append("<td>");
		buf.append("&nbsp;");
		buf.append("&nbsp;");
		buf.append("Invert Match Results: ");
		buf.append("</td>");
		buf.append("<td>");
		buf.append(inverted ? "YES" : "NO");
		buf.append("</td>");
		buf.append("</tr>");

		buf.append("<tr>");
		buf.append("<td>");
		buf.append("&nbsp;");
		buf.append("&nbsp;");
		buf.append("Case Sensitive: ");
		buf.append("</td>");
		buf.append("<td>");
		buf.append(caseSensitive ? "YES" : "NO");
		buf.append("</td>");
		buf.append("</tr>");

		buf.append("<tr>");
		buf.append("<td>");
		buf.append("&nbsp;");
		buf.append("&nbsp;");
		buf.append("Globbing Enabled: ");
		buf.append("</td>");
		buf.append("<td>");
		buf.append(allowGlobbing ? "YES" : "NO");
		buf.append("</td>");
		buf.append("</tr>");

		buf.append("<tr>");
		buf.append("<td>");
		buf.append("&nbsp;");
		buf.append("&nbsp;");
		buf.append("Multi-Term: ");
		buf.append("</td>");
		buf.append("<td>");
		buf.append(isMultiterm() ? "YES" : "NO");
		buf.append("</td>");
		buf.append("</tr>");

		if (isMultiterm()) {
			buf.append("<tr>");
			buf.append("<td>");
			buf.append("&nbsp;");
			buf.append("&nbsp;");
			buf.append("Term Delimiter: ");
			buf.append("</td>");
			buf.append("<td>");

			char delim = getDelimitingCharacter();
			String delimName = DELIMITER_NAME_MAP.get(delim);

			buf.append("'").append(delim).append("'").append("&nbsp; <i>(").append(
				delimName).append(")</i>");
			buf.append("</td>");
			buf.append("</tr>");
		}

		buf.append("</table>");

		return buf.toString();
	}

}
