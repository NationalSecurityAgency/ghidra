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
package docking.widgets.fieldpanel.field;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.support.HighlightFactory;

/**
 * This class provides a TextField implementation that takes multiple
 * AttributedStrings and places as many that will fit on a line without clipping
 * before continuing to the next line.
 */
public class FlowLayoutTextField extends VerticalLayoutTextField {

	/**
	 * This constructor will create a text field that will render one line of
	 * text. If <code>metrics.stringWidth(text) &gt; width</code>, then the text
	 * will be clipped. No wrapping will be performed. If <code>text</code>
	 * contains the highlight string, then it will be highlighted using the
	 * highlight color.
	 * 
	 * @param textElements
	 *            the AttributedStrings to display
	 * @param startX
	 *            the x position to draw the string
	 * @param width
	 *            the max width allocated to this field
	 * @param maxLines
	 *            the max number of lines to display
	 * @param hlFactory
	 *            the highlight factory
	 */
	public FlowLayoutTextField(FieldElement[] textElements, int startX,
			int width, int maxLines, HighlightFactory hlFactory) {
		super(createLineElements(textElements, width), startX, width, maxLines, hlFactory,"");
	}

	private static FieldElement[] createLineElements(FieldElement[] textElements, int width) {
		List<FieldElement> subFields = new ArrayList<FieldElement>();

		int currentIndex = 0;
		while (currentIndex < textElements.length) {
			int numberPerLine = getNumberOfElementsPerLine(textElements, currentIndex, width);
			subFields.add(new CompositeFieldElement(textElements, currentIndex, numberPerLine));
			currentIndex += numberPerLine;
		}

		return subFields.toArray(new FieldElement[subFields.size()]);
	}

	private static int getNumberOfElementsPerLine(FieldElement[] elements, int start, int width) {
		int currentWidth = 0;
		int count = 0;
		int n = elements.length;
		for (int i = start; i < n; i++) {
			currentWidth += elements[i].getStringWidth();
			count++;
			if (currentWidth > width) {
				return Math.max(count - 1, 1);
			}
		}

		return elements.length - start;
	}

}
