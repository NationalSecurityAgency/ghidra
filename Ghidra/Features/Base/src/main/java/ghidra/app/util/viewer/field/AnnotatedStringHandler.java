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

import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.classfinder.ExtensionPoint;

import java.awt.event.MouseEvent;

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.FieldElement;

/**
 * NOTE:  ALL AnnotatedStringHandler CLASSES MUST END IN "StringHandler".  If not,
 * the ClassSearcher will not find them.
 * 
 * An interface that describes a string that has been annotated, which allows for adding
 * rendering and functionality to strings.
 */
public interface AnnotatedStringHandler extends ExtensionPoint {

	public static final AnnotatedMouseHandler DUMMY_MOUSE_HANDLER = new AnnotatedMouseHandler() {
		@Override
		public boolean handleMouseClick(ProgramLocation location, MouseEvent mouseEvent,
				ServiceProvider serviceProvider) {
			return false;
		}
	};

	/**
	 * Creates an {@link FieldElement} based upon the give array of Strings.  The first String
	 * in the list is expected to be the annotation tag used to create the annotation.  At the
	 * very least the array is expected to be comprised of two elements, the annotation and some
	 * data.  Extra data may be provided as needed by implementing classes.
	 *
	 * @param  prototypeString The prototype {@link FieldElement} that dictates the
	 *         attributes for the newly created string.  Implementations may change attributes
	 *         as needed.
	 * @param  text An array of Strings used to create the {@link FieldElement} being
	 *         returned.
	 * @param  program The program with which the returned string is associated. 
	 * @return An {@link AnnotatedTextFieldElement} that will be used to render the given text.
	 * @throws AnnotationException if the given text data does not fit the expected format for
	 *         the given handler implementation.
	 */
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException;

	/**
	 * Returns the annotation string names that this AnnotatedStringHandler supports (e.g., "symbol",
	 * "address", etc...).
	 *
	 * @return the annotation string names that this AnnotatedStringHandler supports.
	 */
	public String[] getSupportedAnnotations();

	/**
	 * A method that is notified when an annotation is clicked.  Returns true if this annotation
	 * handles the click; return false if this annotation does not do anything with the click.
	 *  
	 * @param annotationParts The constituent parts of the annotation
	 * @param sourceNavigatable The location in the program that was clicked.
	 * @param serviceProvider A service provider for needed services.
	 * @return true if this annotation handles the click; return false if this annotation does 
	 *         not do anything with the click.
	 */
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider);

	/**
	 * Returns the String that represents the GUI presence of this option
	 * @return the String to display in GUI components.
	 */
	public String getDisplayString();

	/**
	 * Returns an example string of how the annotation is used
	 * @return the example of how this is used.
	 */
	public String getPrototypeString();
}
