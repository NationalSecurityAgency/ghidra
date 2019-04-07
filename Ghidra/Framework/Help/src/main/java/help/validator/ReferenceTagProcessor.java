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
package help.validator;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.util.*;

import ghidra.util.exception.AssertException;
import help.HelpBuildUtils;
import help.validator.location.HelpModuleLocation;
import help.validator.model.HREF;
import help.validator.model.IMG;

public class ReferenceTagProcessor extends TagProcessor {

	private static final String EOL = System.getProperty("line.separator");
	private static final String STYLESHEET_FILENAME = "Frontpage.css";
	private static final String STYLESHEET_PATHNAME = "shared/" + STYLESHEET_FILENAME;

	private Path htmlFile;
	private Set<Path> styleSheets = new HashSet<>();
	private String title;
	private boolean readingTitle = false;

	private final StringBuffer errors = new StringBuffer();
	private final Path defaultStyleSheet;
	private final AnchorManager anchorManager;
	private final HelpModuleLocation help;
	private int errorCount;

	public ReferenceTagProcessor(HelpModuleLocation help, AnchorManager anchorManager) {
		this.help = help;
		this.anchorManager = anchorManager;

		//
		// Note: currently all help being built has the required stylesheet living under 
		// <help dir>/shared/<stylesheet name>
		// 
		// If we ever need a more robust styling mechanism, then this code would need to be 
		// updated to know how to search for the referenced stylesheet
		Path helpPath = help.getHelpLocation();
		FileSystem fs = helpPath.getFileSystem();
		Path relativeSSPath = fs.getPath(STYLESHEET_PATHNAME);
		defaultStyleSheet = helpPath.resolve(relativeSSPath);
		if (Files.notExists(helpPath)) {
			throw new AssertException("Cannot find expected stylesheet: " + defaultStyleSheet);
		}
	}

	@Override
	public boolean isTagSupported(String tagType) {
		if (tagType == null) {
			return false;
		}

		tagType = tagType.toLowerCase();
		return "a".equals(tagType) || "img".equals(tagType) || "title".equals(tagType) ||
			"/title".equals(tagType) || "link".equals(tagType);
	}

	@Override
	public void processTag(String tagType, LinkedHashMap<String, String> tagAttributes, Path file,
			int lineNum) throws IOException {

		tagType = tagType.toLowerCase();
		if ("a".equals(tagType)) {
			if (tagAttributes.containsKey("href")) {
				try {
					anchorManager.addAnchorRef(
						new HREF(help, file, tagAttributes.get("href"), lineNum));
				}
				catch (URISyntaxException e) {
					errorCount++;
					errors.append(
						"Malformed Anchor Tag at (line " + lineNum + "): " + htmlFile + EOL);
				}
			}
			else if (tagAttributes.containsKey("name")) {
				anchorManager.addAnchor(file, tagAttributes.get("name"), lineNum);
			}
			else {
				errorCount++;
				errors.append("Bad Anchor Tag - unexpected attribtute (line " + lineNum + "): " +
					htmlFile + EOL);
			}
		}
		else if ("img".equals(tagType)) {
			if (tagAttributes.containsKey("src")) {
				try {
					anchorManager.addImageRef(
						new IMG(help, file, tagAttributes.get("src"), lineNum));
				}
				catch (URISyntaxException e) {
					errorCount++;
					errors.append("Malformed IMG Tag at (line " + lineNum + "): " + htmlFile + EOL);
				}
			}
			else {
				errorCount++;
				errors.append("Bad IMG Tag - unexpected attribtute (line " + lineNum + "): " +
					htmlFile + EOL);
			}
		}
		else if ("link".equals(tagType)) {
			String rel = tagAttributes.get("rel");
			if (rel != null && "stylesheet".equals(rel.toLowerCase())) {
// TODO there is at least one help module that has multiple style sheets.  I see no reason to 
//		enforce this constraint:
//				if (hasStyleSheet) {
//					errorCount++;
//					errors.append("Multiple Stylesheets specified: " + htmlFile + EOL);
//				}
//				else {

				String href = tagAttributes.get("href");
				if (href != null) {
					Path css = HelpBuildUtils.getFile(htmlFile, href);
					css = css.normalize();
					styleSheets.add(css); // validated later
				}
//				}
			}
		}
		else if ("title".equals(tagType)) {
			readingTitle = true;
		}
		else if ("/title".equals(tagType)) {
			readingTitle = false;
		}
	}

	@Override
	public String processText(String text) {
		if (readingTitle) {
			text = text.trim();
			if (text.length() != 0) {
				if (title == null) {
					title = text;
				}
				else {
					title = title + " " + text;
				}
			}
		}
		return text;
	}

	@Override
	public void startOfFile(Path localFile) {
		this.htmlFile = localFile;
		title = null;
		styleSheets.clear();
	}

	@Override
	public void endOfFile() {

		if (title == null) {
			errorCount++;
			errors.append("Missing TITLE in: " + htmlFile + EOL);
		}

		if (styleSheets.isEmpty()) {
			errorCount++;
			errors.append("Missing Stylesheet in: " + htmlFile + EOL);
		}

		boolean hasDefaultStyleSheet = false;
		for (Path ss : styleSheets) {
			if (defaultStyleSheet.equals(ss)) {
				hasDefaultStyleSheet = true;
				break;
			}
		}

		if (!hasDefaultStyleSheet) {
			errorCount++;
			errors.append("Incorrect stylesheet defined - none match " + defaultStyleSheet +
				" in file " + htmlFile + EOL);
		}
	}

	public String getErrorText() {
		return errors.toString();
	}

	@Override
	public int getErrorCount() {
		return errorCount;
	}
}
