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
package ghidra.app.util.viewer.field;

import docking.widgets.fieldpanel.field.AbstractTextFieldElement;
import ghidra.util.bean.field.AnnotatedTextFieldElement;

public class AnnotationCommentPart extends CommentPart {

	private Annotation annotation;

	AnnotationCommentPart(String displayText, Annotation annotation) {
		super(displayText);
		this.annotation = annotation;
	}

	@Override
	String getRawText() {
		return annotation.getAnnotationText();
	}

	@Override
	AbstractTextFieldElement createElement(int row, int column) {
		return new AnnotatedTextFieldElement(annotation, row, column);
	}

	@Override
	public String toString() {
		return annotation.toString();
	}
}
