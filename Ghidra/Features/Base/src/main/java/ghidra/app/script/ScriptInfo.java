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
package ghidra.app.script;

import static ghidra.util.HTMLUtilities.*;

import java.io.*;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import org.apache.commons.lang3.StringUtils;

import docking.actions.KeyBindingUtils;
import generic.jar.ResourceFile;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * This class parses the meta-data about a script.
 */
public class ScriptInfo {
	/**
	 * The delimiter used in categories and menu paths.
	 */
	public static final String DELIMITTER = ".";

	static final String AT_AUTHOR = "@author";
	static final String AT_CATEGORY = "@category";
	static final String AT_KEYBINDING = "@keybinding";
	static final String AT_MENUPATH = "@menupath";
	static final String AT_TOOLBAR = "@toolbar";

	// omit from METADATA to avoid pre-populating in new scripts
	private static final String AT_IMPORTPACKAGE = "@importpackage";

	public static final String[] METADATA =
		{ AT_AUTHOR, AT_CATEGORY, AT_KEYBINDING, AT_MENUPATH, AT_TOOLBAR, };

	private GhidraScriptProvider provider;
	private ResourceFile sourceFile;
	private boolean isCompileErrors;
	private boolean isDuplicate;
	private long modified;

	private String description;
	private String author;
	private String[] category = new String[0];
	private KeyStroke keyBinding;
	private String keybindingErrorMessage;
	private String[] menupath = new String[0];
	private String toolbar;
	private ImageIcon toolbarImage;
	private String importpackage;

	/**
	 * Constructs a new script.
	 * @param provider the script provider (for example, java or python)
	 * @param sourceFile the script source file
	 */
	ScriptInfo(GhidraScriptProvider provider, ResourceFile sourceFile) {
		this.provider = provider;
		this.sourceFile = sourceFile;

		if (!sourceFile.exists()) {
			throw new IllegalArgumentException(
				"Source file for script does not exist!: " + sourceFile);
		}
	}

	private void init() {
		description = "";
		author = null;
		category = new String[0];
		keyBinding = null;
		menupath = new String[0];
		toolbar = null;
		toolbarImage = null;
		importpackage = null;
		keybindingErrorMessage = null;
	}

	/**
	 * Setting the toolbar image to null forces it to be reloaded on the next request.
	 */
	public void refresh() {
		this.toolbarImage = null;
	}

	/**
	 * Returns the name of the script.
	 * The name of the script is the file name.
	 * @return the name of the script
	 */
	public String getName() {
		return sourceFile.getName();
	}

	/**
	 * Returns the script source file.
	 * @return the script source file
	 */
	public ResourceFile getSourceFile() {
		return sourceFile;
	}

	/**
	 * Returns the script author information.
	 * @return the script author information.
	 */
	public String getAuthor() {
		parseHeader();
		return author;
	}

	/**
	 * Returns true if the script has compile errors.
	 * @return true if the script has compile errors
	 */
	public boolean isCompileErrors() {
		return isCompileErrors;
	}

	/**
	 * Sets whether the script has compile errors.
	 * @param b true if the script has compile errors
	 */
	public void setCompileErrors(boolean b) {
		isCompileErrors = b;
	}

	/**
	 * Returns true if this script is a duplicate.
	 * When two or more scripts exists with the same name, this
	 * is considered a duplicate script.
	 * @return true if this script is a duplicate
	 */
	public boolean isDuplicate() {
		return isDuplicate;
	}

	/**
	 * Sets whether the script is a duplicate.
	 * @param isDuplicate true if the script is a duplicate
	 */
	public void setDuplicate(boolean isDuplicate) {
		this.isDuplicate = isDuplicate;
	}

	/**
	 * Returns the script description.
	 * @return the script description
	 */
	public String getDescription() {
		parseHeader();
		return description;
	}

	private void parseHeader() {
		if (modified == sourceFile.lastModified()) {
			return;
		}

		if (!sourceFile.exists()) {
			return; // must have been deleted
		}

		init();

		String commentPrefix = provider.getCommentCharacter();

		// Note that skipping certification header presumes that the header
		// is intact with an appropriate start and end
		String certifyHeaderStart = provider.getCertifyHeaderStart();
		boolean allowCertifyHeader = (certifyHeaderStart != null);

		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(sourceFile.getInputStream()))) {
			StringBuilder buffer = new StringBuilder();
			boolean hitAtSign = false;
			while (true) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}

				if (allowCertifyHeader && skipCertifyHeader(reader, line)) {
					allowCertifyHeader = false;
					continue;
				}

				if (parseBlockComment(reader, line)) {
					allowCertifyHeader = false;
					continue; // read block comment; move to next line
				}

				if (line.startsWith(commentPrefix)) {
					allowCertifyHeader = false;

					line = line.substring(commentPrefix.length()).trim();
					if (line.startsWith("@")) {
						hitAtSign = true;
						parseMetaDataLine(line);
					}
					else if (!hitAtSign) {
						// only consume line comments that come before metadata
						buffer.append(line).append(' ').append('\n');
					}
				}
				else if (line.trim().isEmpty()) {
					continue; // allow blank lines between "//" comment sections
				}
				else {
					break;
				}
			}

			description = buffer.toString();
			modified = sourceFile.lastModified();
		}
		catch (IOException e) {
			Msg.debug(this, "Unexpected exception reading script: " + sourceFile, e);
		}
	}

	private boolean skipCertifyHeader(BufferedReader reader, String line) throws IOException {

		// Note that skipping certification header presumes that the header
		// is intact with an appropriate start and end
		String certifyHeaderStart = provider.getCertifyHeaderStart();
		if (certifyHeaderStart == null) {
			return false;
		}

		if (!line.startsWith(certifyHeaderStart)) {
			return false;
		}

		String certifyHeaderEnd = provider.getCertifyHeaderEnd();
		String certifyHeaderBodyPrefix = provider.getCertificationBodyPrefix();
		certifyHeaderBodyPrefix = certifyHeaderBodyPrefix == null ? "" : certifyHeaderBodyPrefix;

		while ((line = reader.readLine()) != null) {

			// Skip past certification header if found
			String trimLine = line.trim();
			if (trimLine.startsWith(certifyHeaderEnd)) {
				return true;
			}

			if (trimLine.startsWith(certifyHeaderBodyPrefix)) {
				continue; // skip certification header body
			}

			// broken certification header - unexpected line
			Msg.error(this,
				"Script contains invalid certification header: " + getName());
		}
		return false;
	}

	private boolean parseBlockComment(BufferedReader reader, String line) throws IOException {
		Pattern blockStart = provider.getBlockCommentStart();
		Pattern blockEnd = provider.getBlockCommentEnd();

		if (blockStart == null || blockEnd == null) {
			return false;
		}

		Matcher startMatcher = blockStart.matcher(line);
		if (startMatcher.find()) {
			int lastOffset = startMatcher.end();
			while (line != null && !blockEnd.matcher(line).find(lastOffset)) {
				line = reader.readLine();
				lastOffset = 0;
			}
			return true;
		}
		return false;
	}

	private void parseMetaDataLine(String line) {
		try {

			if (line.startsWith(AT_AUTHOR)) {
				author = getTagValue(AT_AUTHOR, line);
			}
			else if (line.startsWith(AT_CATEGORY)) {
				String tagValue = getTagValue(AT_CATEGORY, line);
				if (tagValue != null) {
					category = splitString(tagValue, DELIMITTER);
				}
			}
			else if (line.startsWith(AT_KEYBINDING)) {
				String tagValue = getTagValue(AT_KEYBINDING, line);
				if (tagValue != null) {
					setKeyBinding(tagValue);
				}
			}
			else if (line.startsWith(AT_MENUPATH)) {
				String tagValue = getTagValue(AT_MENUPATH, line);
				if (tagValue != null) {
					StringTokenizer nizer = new StringTokenizer(tagValue, DELIMITTER);
					menupath = new String[nizer.countTokens()];
					for (int i = 0; i < menupath.length; i++) {
						menupath[i] = nizer.nextToken().trim();
					}
				}
			}
			else if (line.startsWith(AT_TOOLBAR)) {
				toolbar = getTagValue(AT_TOOLBAR, line);
			}
			else if (line.startsWith(AT_IMPORTPACKAGE)) {
				importpackage = getTagValue(AT_IMPORTPACKAGE, line);
			}
		}
		catch (Exception e) {
			Msg.debug(this, "Unexpected exception reading script metadata " + "line: " + line, e);
		}
	}

	private String getTagValue(String tag, String line) {
		if (line.length() <= tag.length()) {
			return null; // empty tag
		}
		if (line.startsWith(tag)) {
			return line.substring(tag.length() + 1).trim();
		}
		return null;
	}

	private String[] splitString(String string, String delimiter) {
		StringTokenizer nizer = new StringTokenizer(string, delimiter);
		String[] pieces = new String[nizer.countTokens()];
		for (int i = 0; i < pieces.length; i++) {
			pieces[i] = nizer.nextToken().trim();
		}
		return pieces;
	}

	private void setKeyBinding(String line) {
		StringTokenizer tokenizer = new StringTokenizer(line);
		StringBuilder buildy = new StringBuilder();

		// handle case issues for the KeyStroke class:
		int tokenCount = tokenizer.countTokens();
		for (int i = 0; i < tokenCount; i++) {
			String token = tokenizer.nextToken();

			if (i == tokenCount - 1) { // the key char value is the last element 
				// ...all key character values must be upper case
				buildy.append(token.toUpperCase());
			}
			else {
				// ...all modifiers must be lower case
				buildy.append(token.toLowerCase());
				buildy.append(' ');
			}
		}

		keyBinding = KeyBindingUtils.parseKeyStroke(buildy.toString());
		if (keyBinding == null) {
			// note: this message will be cleared by the parseHeader() method
			keybindingErrorMessage = "Unable to parse keybinding: " + buildy;
		}
	}

	/**
	 * Returns true if 'cat' is a category.
	 * @param otherCategory the script category
	 * @return true if 'cat' is a category
	 */
	public boolean isCategory(String[] otherCategory) {
		if (otherCategory == null) {
			return true;//ROOT
		}

		parseHeader();
		if (category.length < otherCategory.length) {
			return false;
		}

		boolean match = true;
		for (int i = 0; i < otherCategory.length; ++i) {
			if (i < category.length) {
				if (!otherCategory[i].equalsIgnoreCase(category[i])) {
					match = false;
					break;
				}
			}
		}
		return match;
	}

	/**
	 * Returns the script category path.
	 * @return the script category path
	 */
	public String[] getCategory() {
		parseHeader();
		return category;
	}

	/**
	 * Returns the script menu path.
	 * @return the script menu path
	 */
	public String[] getMenuPath() {
		parseHeader();
		return menupath;
	}

	/**
	 * Returns the script menu path as a string.
	 * For example,{@literal "Path1->Path2->Path3"}.
	 * @return the script menu path as a string
	 */
	public String getMenuPathAsString() {
		String menuPath = "";
		String[] menuPathArr = getMenuPath();
		for (String path : menuPathArr) {
			if (menuPath.length() > 0) {
				menuPath = menuPath + "->";
			}
			menuPath = menuPath + path;
		}
		return menuPath;
	}

	/**
	 * Returns the script key binding.
	 * @return the script key binding
	 */
	public KeyStroke getKeyBinding() {
		parseHeader();
		return keyBinding;
	}

	/**
	 * @return an error resulting from parsing keybinding metadata 
	 */
	public String getKeyBindingErrorMessage() {
		return keybindingErrorMessage;
	}

	/**
	 * Returns the script tool bar icon.
	 * @param scaled true if the icon should be scaled to 16x16.
	 * @return the script tool bar icon
	 */
	public ImageIcon getToolBarImage(boolean scaled) {
		parseHeader();
		if (toolbar == null) {
			return null;
		}
		if (toolbarImage == null) {
			List<ResourceFile> directories = GhidraScriptUtil.getScriptSourceDirectories();
			for (ResourceFile dir : directories) {
				ResourceFile imageFile = new ResourceFile(dir, toolbar);
				if (imageFile.exists()) {
					toolbarImage = ResourceManager.loadImage(imageFile.getAbsolutePath());
					break;
				}
			}
			if (toolbarImage == null) {
				toolbarImage = ResourceManager.loadImage("images/" + toolbar);
			}
		}
		if (scaled && toolbarImage != null) {
			return ResourceManager.getScaledIcon(toolbarImage, 16, 16);
		}
		return toolbarImage;
	}

	/**
	 * Returns the script imports
	 * @return the script imports
	 */
	public String getImportPackage() {
		parseHeader();
		return importpackage;
	}

	/**
	 * Returns a string designed to be used as a tool tip for describing this script
	 * @return a string designed to be used as a tool tip
	 */
	public String getToolTipText() {
		parseHeader();
		String htmlDescription = "No Description";
		if (description != null) {
			htmlDescription = escapeHTML(description);
			htmlDescription = htmlDescription.replaceAll("\n", HTML_NEW_LINE + HTML_SPACE);
		}

		String space = HTML_SPACE;
		String htmlAuthor = bold("Author:") + space + escapeHTML(toString(author));
		String htmlCategory = bold("Category:") + space + escapeHTML(toString(category));
		String htmlKeyBinding = bold("Key Binding:") + space + getKeybindingToolTip();
		String htmlMenuPath = bold("Menu Path:") + space + escapeHTML(toString(menupath));

		StringBuilder buffer = new StringBuilder();
		buffer.append("<h3>").append(space).append(escapeHTML(getName())).append("</h3>");
		buffer.append(HTML_NEW_LINE);
		buffer.append(space).append(htmlDescription);
		buffer.append(HTML_NEW_LINE);
		buffer.append(HTML_NEW_LINE);
		buffer.append(space).append(htmlAuthor);
		buffer.append(HTML_NEW_LINE);
		buffer.append(space).append(htmlCategory);
		buffer.append(HTML_NEW_LINE);
		buffer.append(space).append(htmlKeyBinding);
		buffer.append(HTML_NEW_LINE);
		buffer.append(space).append(htmlMenuPath);
		buffer.append(HTML_NEW_LINE);
		buffer.append(HTML_NEW_LINE);
		return wrapAsHTML(buffer.toString());
	}

	private String getKeybindingToolTip() {
		return toToolTip(getKeyBinding());
	}

	private String toToolTip(KeyStroke keyStroke) {
		if (keyStroke == null) {
			if (keybindingErrorMessage != null) {
				return keybindingErrorMessage;
			}
			return "";
		}
		return KeyBindingUtils.parseKeyStroke(keyStroke);
	}

	private String toString(String string) {
		return StringUtils.defaultString(string);
	}

	private String toString(String[] path) {
		String joined = StringUtils.join(path, DELIMITTER);
		return StringUtils.defaultString(joined);
	}

	/**
	 * @return true if the script either has compiler errors, or is a duplicate
	 */
	public boolean hasErrors() {
		return isCompileErrors() || isDuplicate();
	}

	/**
	 * @return a generic error message
	 */
	public String getErrorMessage() {
		if (isCompileErrors()) {
			return "Error compiling script (see console)";
		}

		if (isDuplicate()) {
			return "Script is a duplicate of another script";
		}

		return null;
	}

	@Override
	public String toString() {
		return "ScriptInfo: " + getName();
	}
}
