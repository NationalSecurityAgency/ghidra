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

import java.io.File;

public class TutorialScreenShotGenerator extends AbstractScreenShotGenerator {

	//
	// TODO: put the root path to the tutorial images here so that saving and showing images 
	//       is easier
	//

	public TutorialScreenShotGenerator() {
		super();
	}

	/**
	 * @deprecated
	 * 
	 * NOTE:  Please do not remove this until we have decided how to create a showImage() method
	 *        that is compatible with screenshots NOT in Help (ahem, Tutorial!!!).
	 */
	@Deprecated
	public void showImage() {
		ImageDialogProvider dialog = new ImageDialogProvider(null, null, image);
		tool.showDialog(dialog);
	}

	protected void saveToFile(String absolutePathToImage) {
		File imageFile = new File(absolutePathToImage);
		writeFile(imageFile);
	}

//
//	/**
//	 * @deprecated use instead {@link #finished(String, String)}.  
//	 * 
//	 * @param helpTopic The help topic that contains the image
//	 * @param oldImageName  The name of the image
//	 */
//	@Deprecated
//	public void showImage(String helpTopic, String oldImageName) {
//		doShowImage(helpTopic, oldImageName);
//	}
//
//	private void doShowImage(String helpTopic, String oldImageName) {
//		if (SAVE_CREATED_IMAGE_FILE) {
//			Msg.error(this, "Do not call showImage() directly");
//			return;
//		}
//
//		Image oldImage = getOldImage(helpTopic, oldImageName);
//		ImageDialogProvider dialog = new ImageDialogProvider(oldImage, image);
//		tool.showDialog(dialog, tool.getToolFrame());
//	}
//
//	private Image getOldImage(String helpTopic, String imageName) {
//		File helpTopicDir = getHelpTopicDir(helpTopic);
//		if (helpTopicDir == null) {
//			throw new AssertException("Invalid help topic name: " + helpTopic);
//		}
//
//		File imageFile = new File(helpTopicDir, "/images/" + imageName);
//		if (!imageFile.exists()) {
//			throw new AssertException("Cannot find image " + imageName + " in help topic " +
//				helpTopic);
//		}
//
//		return readImage(imageFile);
//	}

}
