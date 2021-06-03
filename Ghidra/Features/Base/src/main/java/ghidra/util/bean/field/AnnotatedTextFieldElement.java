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
package ghidra.util.bean.field;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.viewer.field.Annotation;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;

/**
 * A subclass of {@link FieldElement} that allows for mouse handling callbacks via the 
 * {@link #handleMouseClicked(Navigatable, ServiceProvider)} method.  This class
 * is based upon {@link Annotation} objects, which are elements that perform actions when the 
 * use clicks an instance of this class in the display.
 */
final public class AnnotatedTextFieldElement extends AbstractTextFieldElement {

	private final Annotation annotation;

	// this is for our local substring type methods
	private AnnotatedTextFieldElement(Annotation annotation, AttributedString displayString,
			int row, int column) {
		super(displayString, row, column);
		this.annotation = annotation;
	}

	/**
	 * Constructor that initializes this text field element with the given annotation and row
	 * and column information.  The text of this element is the text returned from
	 * {@link Annotation#getDisplayString()}.
	 * 
	 * @param annotation The Annotation that this element is describing.
	 * @param row The row that this element is on
	 * @param column The column value of this element (the column index where this element starts)
	 */
	public AnnotatedTextFieldElement(Annotation annotation, int row, int column) {
		this(annotation, annotation.getDisplayString(), row, column);
	}

	/**
	 * Returns the original annotation text in the data model, which will differ from the display
	 * text.
	 * @return the original annotation text in the data model.
	 */
	public String getRawText() {
		return annotation.getAnnotationText();
	}

	/**
	 * This method is designed to be called when a mouse click has occurred for a given 
	 * {@link ProgramLocation}.
	 * 
	 * @param sourceNavigatable The source Navigatable
	 * @param serviceProvider A service provider from which system resources can be retrieved
	 * @return true if this string handles the mouse click.
	 */
	public boolean handleMouseClicked(Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {
		return annotation.handleMouseClick(sourceNavigatable, serviceProvider);
	}

	@Override
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		return new RowColLocation(row, column);
	}

	@Override
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		if (row == dataRow) {
			if (dataColumn >= column && dataColumn < column + attributedString.length()) {
				return 0;
			}
		}
		return -1;
	}

	@Override
	public FieldElement substring(int start, int end) {
		AttributedString as = attributedString.substring(start, end);
		if (as == attributedString) {
			return this;
		}
		return new AnnotatedTextFieldElement(annotation, as, row, column + start);
	}

	@Override
	public FieldElement replaceAll(char[] targets, char replacement) {
		return new AnnotatedTextFieldElement(annotation,
			attributedString.replaceAll(targets, replacement), row, column);
	}
}
