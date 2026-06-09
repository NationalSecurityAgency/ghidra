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
package docking.widgets.textfield;

import java.awt.FontMetrics;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link PreviewTextField} (JTextField) that has a preview that compresses / shortens the
 * text in the field using rules that are tuned to preserve human readability of filename path info.
 * <p>
 * Longer directory names are truncated and modified to have a "..." suffix.  When adjacent 
 * directory names have been reduced to just "...", they are combined into a single "...." (4-dot).
 * <p>
 * The first and last directory elements in the path are given preference and will be subject to
 * shortening after interior directory name elements.
 * <p>
 * The final element in the path (filename) is always preserved.
 * <p>
 * If the preview of the path needs truncation, the full path will be temporarily appended to the
 * the field's tool tip.
 */
public class ElidingFilePathTextField extends PreviewTextField {
	private static final int ELLIPSE_LEN = "...".length();

	/**
	 * Creates a new {@link ElidingFilePathTextField} instance with no text.
	 */
	public ElidingFilePathTextField() {
		this(null, null);
	}

	/**
	 * Creates a new {@link ElidingFilePathTextField} instance with specified text value.
	 * @param text string to assign as initial value of text field
	 */
	public ElidingFilePathTextField(String text) {
		this(text, null);
	}

	/**
	 * Creates a new {@link ElidingFilePathTextField} instance with specified text and hint values.
	 * @param text string to assign as initial value of text field
	 * @param hint string to assign as the hint value that is shown when the field is blank
	 */
	public ElidingFilePathTextField(String text, String hint) {
		super(text, hint, false, null);
	}

	record PathPartInfo(int origIndex, String s) {
		int getLen(String[] pathParts) {
			String partStr = pathParts[origIndex];
			return partStr != null ? partStr.length() : ELLIPSE_LEN;
		}

		static int pathPartCompare(String[] pathParts, PathPartInfo ppi1, PathPartInfo ppi2,
				boolean boostOutsideElements) {
			int s1len = ppi1.getLen(pathParts);
			int s2len = ppi2.getLen(pathParts);
			if (boostOutsideElements) {
				// make the first and last couple of elements in the path seem shorter than they are
				// to tweak the output and preserve those elements if possible
				if (ppi1.origIndex < 2 || ppi1.origIndex > pathParts.length - 3) {
					s1len = s1len / 2;
				}
				if (ppi2.origIndex < 2 || ppi2.origIndex > pathParts.length - 3) {
					s2len = s2len / 2;
				}
			}
			return Integer.compare(s1len, s2len);
		}

	}

	protected boolean isShortEnough(String s, FontMetrics fm, int maxWidth) {
		return fm.stringWidth(s) < maxWidth;
	}

	@Override
	protected String getPreviewString(String s, FontMetrics fm, int maxWidth) {
		String[] pathParts = s.split("/");
		if (pathParts.length < 2) {
			return s;
		}

		// list of path elements, sorted by string length, longer first
		List<PathPartInfo> sortedParts = new ArrayList<>();
		for (int i = 0; i < pathParts.length - 1 /* skip filename/last element */; i++) {
			sortedParts.add(new PathPartInfo(i, pathParts[i]));
		}
		sortedParts.sort((s1, s2) -> PathPartInfo.pathPartCompare(pathParts, s2, s1, true));

		String result = s;
		// first try abbreviating the longer parts until the path is short enough
		for (PathPartInfo ppi : sortedParts) {
			if (ppi.getLen(pathParts) <= ELLIPSE_LEN) {
				break;
			}
			String part = pathParts[ppi.origIndex];
			for (int i = part.length() - ELLIPSE_LEN; i >= 0; i--) {
				pathParts[ppi.origIndex] = i > 0 ? part.substring(0, i) + "..." : null;
				result = partsToString(pathParts);
				if (isShortEnough(result, fm, maxWidth)) {
					return result; // success
				}
			}
		}

		// finally just start indiscriminately removing elements until it fits
		for (PathPartInfo ppi : sortedParts) {
			if (pathParts[ppi.origIndex] == null) {
				continue;
			}
			pathParts[ppi.origIndex] = null;
			result = partsToString(pathParts);
			if (isShortEnough(result, fm, maxWidth)) {
				break; // fall thru, return result
			}
		}

		return result;
	}

	private String partsToString(String[] pathParts) {
		// create a pseudo path string from the array of path parts
		// runs of null elements are represented by "....", single null element by "..."
		// will have a leading '/' if the first element of the array is blank ""
		StringBuilder sb = new StringBuilder();
		int nullrun = 0;
		for (int i = 0; i < pathParts.length; i++) {
			String part = pathParts[i];
			if (part != null) {
				if (i == 0 && part.isEmpty()) {
					// leading empty element means there was a leading '/' in the path
					if (pathParts.length < 2 || pathParts[1] != null) {
						// only output leading '/' if next path element is defined
						part = "/";
					}
				}
				if (nullrun != 0) {
					appendPath(sb, nullrun == 1 ? "..." : "....");
					nullrun = 0;
				}
				appendPath(sb, part);
			}
			else {
				nullrun++;
			}
		}
		return sb.toString();
	}

	private void appendPath(StringBuilder sb, String s) {
		if (!sb.isEmpty() && sb.charAt(sb.length() - 1) != '/') {
			sb.append('/');
		}
		sb.append(s);
	}

}
