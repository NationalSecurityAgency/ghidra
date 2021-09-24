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

import java.util.*;

import docking.widgets.fieldpanel.support.HighlightFactory;

/**
 * This class provides a TextField implementation that takes multiple AttributedString field
 * elements and places as many that will fit on a line without clipping before continuing to the
 * next line.
 */
public class FlowLayoutTextField extends VerticalLayoutTextField {

	/**
	 * This constructor will create a text field that will render one line of text. If
	 * <code>metrics.stringWidth(text) &gt; width</code>, then the text will be wrapped.
	 * If <code>text</code> contains the highlight string, then it will be highlighted using the
	 * highlight color.
	 * 
	 * @param textElements the AttributedStrings to display
	 * @param startX the x position to draw the string
	 * @param width the max width allocated to this field
	 * @param maxLines the max number of lines to display
	 * @param hlFactory the highlight factory
	 * @deprecated use the constructor that takes a list
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	public FlowLayoutTextField(FieldElement[] textElements, int startX,
			int width, int maxLines, HighlightFactory hlFactory) {
		this(Arrays.asList(textElements), startX, width, maxLines, hlFactory);
	}

	/**
	 * This constructor will create a text field that will render one line of text. If
	 * <code>metrics.stringWidth(text) &gt; width</code>, then the text will be wrapped.
	 * If <code>text</code> contains the highlight string, then it will be highlighted using the
	 * highlight color.
	 * 
	 * @param elements the AttributedStrings to display
	 * @param startX the x position to draw the string
	 * @param width the max width allocated to this field
	 * @param maxLines the max number of lines to display
	 * @param hlFactory the highlight factory
	 */
	public FlowLayoutTextField(List<FieldElement> elements, int startX,
			int width, int maxLines, HighlightFactory hlFactory) {
		super(createLineElements(elements, width), startX, width, maxLines, hlFactory, "");
	}

	private static List<FieldElement> createLineElements(List<FieldElement> elements,
			int width) {
		List<FieldElement> subFields = new ArrayList<>();
		int currentIndex = 0;
		while (currentIndex < elements.size()) {
			int numberPerLine = getNumberOfElementsPerLine(elements, currentIndex, width);
			subFields.add(createLineFromElements(elements, currentIndex, numberPerLine));
			currentIndex += numberPerLine;
		}

		return subFields;
	}

	@Override
	protected TextField createFieldForLine(FieldElement element) {
		CompositeFieldElement composite = (CompositeFieldElement) element;
		int numDataRows = composite.getNumElements();
		return new ClippingTextField(startX, width, element, numDataRows, hlFactory);
	}

	private static CompositeFieldElement createLineFromElements(List<FieldElement> elements,
			int start, int length) {
		return new CompositeFieldElement(elements.subList(start, start + length));
	}

	private static int getNumberOfElementsPerLine(List<FieldElement> elements, int start,
			int width) {

		int currentWidth = 0;
		for (int i = start; i < elements.size(); i++) {
			FieldElement element = elements.get(i);
			currentWidth += element.getStringWidth();
			if (currentWidth > width) {
				int count = i - start;
				return Math.max(count, 1);
			}
		}
		return elements.size() - start;
	}

}
