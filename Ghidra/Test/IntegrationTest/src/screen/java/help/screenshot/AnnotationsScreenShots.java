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
package help.screenshot;

import org.junit.Test;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.comments.CommentsDialog;
import ghidra.app.util.viewer.field.EolCommentFieldFactory;

public class AnnotationsScreenShots extends GhidraScreenShotGenerator {

	public AnnotationsScreenShots() {
		super();
	}

	@Test
	public void testCommentDialogURLExample() {
		goToListing(0x00407716, "Address", true);
		showCommentDialog(
			"The link below is an example of a URL annotation:\n{@url http://www.google.com}");
		captureDialog();
	}

	@Test
	public void testInvalidAnnotationsDialogExample() {
		goToListing(0x00407716, "Address", true);
		showCommentDialog("Bad annotations:\n{@unknown smile}\n{@sym }");
		captureDialog();
	}

	@Test
	public void testRenderedInvalidAnnotation() throws Exception {
		String fieldName = EolCommentFieldFactory.FIELD_NAME;
		setListingFieldWidth(fieldName, 400);

		setCommentFieldText("Bad annotations:\n{@unknown smile}\n{@sym }");

		captureListingField(0x00407716, fieldName, 100);
	}

	@Test
	public void testRenderedURLExample() throws Exception {
		String fieldName = EolCommentFieldFactory.FIELD_NAME;
		setListingFieldWidth(fieldName, 400);

		setCommentFieldText(
			"The link below is an example of a URL annotation:\n{@url http://www.google.com}");

		captureListingField(0x00407716, fieldName, 100);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void setCommentFieldText(String text) {
		CodeBrowserPlugin plugin = getPlugin(tool, CodeBrowserPlugin.class);
		plugin.goToField(addr(0x00407716), "Address", 0, 0);
		performAction("Set EOL Comment", "CommentsPlugin", false);
		CommentsDialog dialog = (CommentsDialog) getDialog();
		prepareCommentsDialog(dialog, text);
		pressButtonByText(dialog, "OK");
	}
}
