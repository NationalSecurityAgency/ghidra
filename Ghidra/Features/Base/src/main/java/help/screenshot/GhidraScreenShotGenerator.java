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

import static org.junit.Assert.assertNotNull;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.After;
import org.junit.Assert;

import docking.*;
import docking.action.DockingActionIf;
import generic.jar.ResourceFile;
import generic.util.WindowUtilities;
import ghidra.framework.Application;
import ghidra.framework.main.FrontEndTool;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public abstract class GhidraScreenShotGenerator extends AbstractScreenShotGenerator {

	private static final String CAPTURE = "Capture";

	protected GhidraScreenShotGenerator() {
		super();
	}

	@Override
	@After
	public void tearDown() throws Exception {

		super.tearDown();

		showResults();
	}

	protected void showResults() {
		if (!hasTestFailed()) {
			saveOrDisplayImage();
		}
		else {
			Msg.error(this, "Not showing screenshot results--test failed " + getName());
		}
	}

	/** 
	 * Generally, you shouldn't use this.  This is only visible for those who do not directly
	 * extend this class.
	 */
	public void saveOrDisplayImage() {
		String name = testName.getMethodName();
		saveOrDisplayImage(name);
	}

	public void saveOrDisplayImage(String name) {

		// strip off the initial 'test'
		name = name.substring(4);

		// we allow also the form 'testCapture...'
		if (name.startsWith(CAPTURE)) {
			name = name.substring(CAPTURE.length());
		}

		// validate our name matches an existing image
		File topic = getHelpTopic();
		File imageFile = getImageFile(topic, name);
		finished(topic, imageFile.getName());
	}

	private File getImageFile(File helpTopic, String name) {
		File potentialFile = new File(helpTopic, "images/" + name + ".png");
		if (potentialFile.exists()) {
			return potentialFile;
		}

		// next, try the .gif extension
		potentialFile = new File(helpTopic, "images/" + name + ".gif");
		if (potentialFile.exists()) {
			handleGIFImage(potentialFile);
		}

		// next, how about jpg?
		potentialFile = new File(helpTopic, "images/" + name + ".jpg");
		if (potentialFile.exists()) {
			handleJPGImage(potentialFile);
		}

		// next, look for any matching image, ignoring case
		final String nameLowerCase = name.toLowerCase();
		File imagesDir = new File(helpTopic, "images");
		File[] matchingFiles = imagesDir.listFiles((FileFilter) f -> {
			String filename = f.getName();
			String filenameLowerCase = filename.toLowerCase();
			return nameLowerCase.equals(filenameLowerCase);
		});

		if (matchingFiles.length == 1) {
			return matchingFiles[0];
		}

		if (matchingFiles.length == 0) {
//			fail("Unable to find image by name (case-insensitive): " + name + " for test case: " +
//				getName());
			return new File("ImageNotFound/" + name + ".png");
		}

		Assert.fail("Found multiple files, ignoring case, that match name: " + name +
			" for test case: " + testName.getMethodName());
		return null;// can't get here
	}

	protected void handleGIFImage(File gifFile) {
		String gifName = gifFile.getName();
		String pngName = gifName.replace(".gif", ".png");
		File pngFile = new File(gifFile.getParentFile(), pngName);

		// write the png out, so that we can replace the gif, if we wish
		writeFile(pngFile);

		Image gifImage = getGIFImage(gifFile);
		showGIFImage(pngFile, gifImage);

		Assert.fail("No PNG, but did find ** GIF ** for test case: " + testName.getMethodName() +
			"\nWriting png image: " + pngFile);
	}

	private void handleJPGImage(File jpgFile) {
		String gifName = jpgFile.getName();
		String pngName = gifName.replace(".jpg", ".png");
		File pngFile = new File(jpgFile.getParentFile(), pngName);

		// write the png out, so that we can replace the gif, if we wish
		writeFile(pngFile);

		Image gifImage = getJPGImage(jpgFile);
		showGIFImage(pngFile, gifImage);

		Assert.fail("No PNG, but did find ** JPG ** for test case: " + testName.getMethodName() +
			"\nWriting png image: " + pngFile);
	}

	protected File getHelpTopic() {
		String topicName = getHelpTopicName();
		File helpTopicDir = getHelpTopicDir(topicName);
		assertNotNull("Unable to find help topic for test file: " + getClass().getName(),
			helpTopicDir);
		return helpTopicDir;
	}

	public void loadDefaultTool() {
		env.launchDefaultTool();
	}

	protected String getHelpTopicName() {
		Class<? extends GhidraScreenShotGenerator> clazz = getClass();
		String simpleName = clazz.getSimpleName();
		return simpleName.replace("ScreenShots", "");
	}

	/**
	 * Call when you are finished generating a new image.  This method will either show the 
	 * newly created image or write it to disk, depending upon the value of 
	 * {@link #SAVE_CREATED_IMAGE_FILE}, which is a system property.
	 * 
	 * @param helpTopic The help topic that contains the image
	 * @param oldImageName  The name of the image
	 */
	public void finished(File helpTopic, String oldImageName) {
		if (SAVE_CREATED_IMAGE_FILE) {
			maybeSaveToHelp(helpTopic, oldImageName);
		}
		else {
			doShowImage(helpTopic, oldImageName);
		}
	}

	private void doShowImage(File helpTopic, String oldImageName) {
		if (SAVE_CREATED_IMAGE_FILE) {
			Msg.error(this, "Do not call showImage() directly");
			return;
		}

		assertNotNull("No new image found", image);

		Image oldImage = getOldImage(helpTopic, oldImageName);
		File imageFile = new File(helpTopic, "/images/" + oldImageName + DEFAULT_FILENAME_SUFFIX);
		ImageDialogProvider dialog = new ImageDialogProvider(imageFile, oldImage, image);
		dialog.setTitle("help/topics/" + helpTopic.getName() + "/images/" + oldImageName);
		showDialog(dialog);
	}

	private void showGIFImage(File imageFile, Image gifImage) {
		ImageDialogProvider dialog = new ImageDialogProvider(imageFile, gifImage, image);
		showDialog(dialog);
	}

	private void showDialog(final DialogComponentProvider dialogComponent) {
		runSwing(() -> {
			DockingDialog dialog = DockingDialog.createDialog(null, dialogComponent, null);
			dialog.setLocation(WindowUtilities.centerOnScreen(dialog.getSize()));
			dialog.setVisible(true);
		});
	}

	protected Image getOldImage(File helpTopicDir, String imageName) {
		if (helpTopicDir == null) {
			throw new AssertException("Invalid help topic name - null");
		}

		File imageFile = new File(helpTopicDir, "/images/" + imageName);
		if (!imageFile.exists()) {
//			throw new AssertException("Cannot find image " + imageName + " in help topic " +
//				helpTopicDir);
			return createEmptyImage(10, 10);
		}

		return readImage(imageFile);
	}

	private Image getGIFImage(File imageFile) {
		BufferedImage gifImage = readImage(imageFile);
		Graphics2D g = (Graphics2D) gifImage.getGraphics();

		int width = gifImage.getWidth();
		int height = gifImage.getHeight();

		Font font = g.getFont().deriveFont((float) (height * .3));
		g.setFont(font);

		String text = "GIF!";
		FontMetrics fontMetrics = g.getFontMetrics(font);
		Rectangle bounds = fontMetrics.getStringBounds(text, g).getBounds();
		int stringWidth = (int) bounds.getWidth();
		int stringHeight = (int) bounds.getHeight();

		int x = (width / 2) - (stringWidth / 2);
		int y = (height / 2) + (stringHeight / 2);
		g.setColor(new Color(0, 0, 200, 100));
		g.drawString(text, x, y);

		return gifImage;
	}

	private Image getJPGImage(File imageFile) {
		BufferedImage gifImage = readImage(imageFile);
		Graphics2D g = (Graphics2D) gifImage.getGraphics();

		int width = gifImage.getWidth();
		int height = gifImage.getHeight();

		Font font = g.getFont().deriveFont((float) (height * .3));
		g.setFont(font);

		String text = "JPG!";
		FontMetrics fontMetrics = g.getFontMetrics(font);
		Rectangle bounds = fontMetrics.getStringBounds(text, g).getBounds();
		int stringWidth = (int) bounds.getWidth();
		int stringHeight = (int) bounds.getHeight();

		int x = (width / 2) - (stringWidth / 2);
		int y = (height / 2) + (stringHeight / 2);
		g.setColor(new Color(0, 0, 200, 100));
		g.drawString(text, x, y);

		return gifImage;
	}

	/**
	 * @deprecated use instead {@link #finished(File, String)}.  
	 * 
	 * @param helpTopic The help topic that contains the image
	 * @param oldImageName  The name of the image
	 */
	@Deprecated
	public void showImage(String helpTopic, String oldImageName) {
		doShowImage(getHelpTopicDir(helpTopic), oldImageName);
	}

	/**
	 * @deprecated use instead {@link #finished(File, String)}.  
	 * 
	 * @param helpTopic The help topic that contains the image
	 * @param imageName  The name of the image
	 */
	@Deprecated
	public void saveToHelp(String helpTopic, String imageName) {
		maybeSaveToHelp(getHelpTopicDir(helpTopic), imageName);
	}

	private void maybeSaveToHelp(File helpTopicDir, String imageName) {
		if (!SAVE_CREATED_IMAGE_FILE) {
			Msg.error(this, "Do not call saveToHelp() directly");
			return;
		}

		reallySaveToHelp(helpTopicDir, imageName);
	}

	protected void reallySaveToHelp(File helpTopicDir, String imageName) {
		Msg.debug(this, "\n\n\t\tWARNING!!!!\nOnly call this method if you need an " +
			"'out of band' help image saved.  If you don't know what that means, then don't!");

		if (helpTopicDir == null) {
			throw new AssertException("Invalid help topic name - null");
		}

		File imageFile = new File(helpTopicDir, "/images/" + imageName + NEW_FILENAME_SUFFIX);
		writeFile(imageFile);
	}

	protected File getHelpTopicDir(String helpTopic) {
		List<File> helpTopicDirs = getHelpTopicDirs();
		for (File file : helpTopicDirs) {
			File potential = new File(file, helpTopic);
			if (potential.exists()) {
				return potential;
			}
		}
		return null;
	}

	protected List<File> getHelpTopicDirs() {
		List<File> helpTopicDirs = new ArrayList<>();
		Collection<ResourceFile> modules = Application.getModuleRootDirectories();
		for (ResourceFile file : modules) {
			File potential = new File(file.getFile(false), "src/main/help/help/topics");
			if (potential.exists()) {
				helpTopicDirs.add(potential);
			}
		}
		return helpTopicDirs;
	}

	protected FrontEndTool getFrontEndTool() {
		final FrontEndTool frontEndTool = env.getFrontEndTool();
		runSwing(() -> frontEndTool.setVisible(true));
		return frontEndTool;
	}

	public void performFrontEndAction(String actionName, String owner, boolean wait) {
		FrontEndTool frontEnd = getFrontEndTool();

		DockingActionIf action = getAction(frontEnd, owner, actionName);
		ComponentProvider compProvider =
			(ComponentProvider) getInstanceField("compProvider", frontEnd);
		performAction(action, compProvider, wait);
	}
}
