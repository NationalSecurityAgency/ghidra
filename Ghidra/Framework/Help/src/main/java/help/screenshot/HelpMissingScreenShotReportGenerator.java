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

import help.GHelpBuilder;
import help.HelpBuildUtils;
import help.validator.UnusedHelpImageFileFinder;
import help.validator.location.DirectoryHelpModuleLocation;
import help.validator.location.HelpModuleLocation;
import help.validator.model.HelpTopic;
import help.validator.model.IMG;

import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map.Entry;

import javax.imageio.ImageIO;

public class HelpMissingScreenShotReportGenerator {

	private static boolean debugEnabled;
	private static final String DEBUG_OPTION = "-debug";
	private static final String SCREEN_SHOTS = "ScreenShots";

	private static final String PNG_EXT = ".png";
	private static final String JAVA_DIR = "java";
	private static final String TEST = "test";
	private static final String CAPTURE = "Capture";
	private static final String CUSTOM_NAME = "Custom";

	public static void main(String[] args) throws Exception {

		if (args.length < 3) {
			throw new Exception(
				"Expecting at least 3 args: <output file path> <help modules> <screen shot tests> [" +
					DEBUG_OPTION + "]");
		}

		for (String arg : args) {
			if (arg.equalsIgnoreCase(DEBUG_OPTION)) {
				debugEnabled = true;
			}
		}

		HelpMissingScreenShotReportGenerator generator =
			new HelpMissingScreenShotReportGenerator(args[0], args[1], args[2]);

		generator.generateReport();
	}

	private Set<HelpModuleLocation> helpDirectories = new HashSet<HelpModuleLocation>();
	private Map<String, HelpTopic> topicNameToTopic = new HashMap<String, HelpTopic>();
	private Set<HelpTestCase> testCases = new HashSet<HelpTestCase>();
	private Map<String, HelpTestCase> imageNameToTestCase = new HashMap<String, HelpTestCase>();

	private SortedSet<String> badlyNamedTestFiles = new TreeSet<String>();
	private SortedSet<HelpTestCase> badlyNamedTestCases = new TreeSet<HelpTestCase>();
//	private Map<HelpDirectory, IMG> untestedImages = new TreeMap<HelpDirectory, IMG>();
	private Map<HelpTopic, Set<IMG>> untestedImages = new TreeMap<HelpTopic, Set<IMG>>();

	private Set<Path> examinedImageFiles = new HashSet<Path>();

	private File outputFile;

	HelpMissingScreenShotReportGenerator(String outputFilePath, String helpModulePaths,
			String screenShotPaths) {
		this.outputFile = new File(outputFilePath);

		parseHelpDirectories(helpModulePaths);

		parseScreenShots(screenShotPaths);

		validateScreenShotTests();

		validateHelpImages();
	}

	void generateReport() {
		outputFile.getParentFile().mkdirs(); // make sure the folder exists

		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(outputFile));
			doGenerateReport(writer);
			System.out.println("Report written to " + outputFile);
		}
		catch (Exception e) {
			errorMessage("FAILED!", e);
		}
		finally {
			if (writer != null) {
				try {
					writer.close();
				}
				catch (IOException e1) {
					// don't care
				}
			}
		}
	}

	private void doGenerateReport(BufferedWriter writer) throws IOException {
		writeHeader(writer);

		writer.write("<P>\n");

		//
		// Total Image File Count 
		//		
		int untestedCount = 0;
		Collection<Set<IMG>> values = untestedImages.values();
		for (Set<IMG> set : values) {
			untestedCount += set.size();
		}

		int totalImageCount = imageNameToTestCase.size() + untestedCount;

		writer.write("<H3>\n");
		writer.write("Total Image Count: " + totalImageCount + "\n");
		writer.write("</H3>\n");

		//
		// All Tested Images
		// 
		writer.write("<H3>\n");
		writer.write("Total Tested Images: " + imageNameToTestCase.size() + "\n");
		writer.write("</H3>\n");

		//
		// Badly Named Test Files
		//

		writer.write("<H3>\n");
		writer.write("Improperly Named Test Files: " + badlyNamedTestFiles.size() + "\n");
		writer.write("</H3>\n");

		writer.write("<P>\n");
		writer.write("<TABLE BORDER=\"1\">\n");

		for (String filename : badlyNamedTestFiles) {

			writer.write("    <TR>\n");

			writer.write("        <TD>\n");
			writer.write("            ");
			writer.write(filename);
			writer.write('\n');
			writer.write("        </TD>\n");
			writer.write("    </TR>\n");
		}

		writer.write("</TABLE>\n");
		writer.write("</P>\n");

		//
		// Badly Named Test Cases
		//

		writer.write("<H3>\n");
		writer.write("Improperly Named Test Cases: " + badlyNamedTestCases.size() + "\n");
		writer.write("</H3>\n");

		writer.write("<P>\n");
		writer.write("<TABLE BORDER=\"1\">\n");

		writer.write("    <TH>\n");
		writer.write("        Test Case\n");
		writer.write("    </TH>\n");
		writer.write("    <TH>\n");
		writer.write("        Image Name\n");
		writer.write("    </TH>\n");

		String lastTopicName = null;
		for (HelpTestCase testCase : badlyNamedTestCases) {

			writer.write("    <TR>\n");

			writer.write("        <TD>\n");
			writer.write("            ");
			String topicName = testCase.getHelpTopic().getName();
			if (!topicName.equals(lastTopicName)) {
				lastTopicName = topicName;
				writer.write(topicName);
				writer.write('\n');
			}
			else {
				writer.write("&nbsp;\n");
			}

			writer.write("        </TD>\n");

			writer.write("        <TD>\n");
			writer.write("            ");
			writer.write(testCase.getTestName());
			writer.write("()\n");
			writer.write("        </TD>\n");
			writer.write("    </TR>\n");
		}

		writer.write("</TABLE>\n");
		writer.write("</P>\n");

		//
		// All Untested Images
		//

		File untestedOutputFile = new File(outputFile.getParentFile(), "_untested.images.html");

		writer.write("<H3>\n");
		writer.write("<A HREF=\"" + untestedOutputFile.getName() + "\">Total Untested Images: " +
			untestedCount + "</A>\n");
		writer.write("</H3>\n");

		generateUntestedImagesFile(untestedOutputFile);

		//
		// All Unused Images
		//

		Set<Path> unusedImages = getUnusedImages();

		writer.write("<H3>\n");
		writer.write("Total Unused Images: " + unusedImages.size() + "\n");
		writer.write("</H3>\n");

		writer.write("<P>\n");
		writer.write("<TABLE BORDER=\"1\">\n");

		writer.write("    <TH>\n");
		writer.write("        Help Topic\n");
		writer.write("    </TH>\n");
		writer.write("    <TH>\n");
		writer.write("        Image Name\n");
		writer.write("    </TH>\n");

		for (Path imageFile : unusedImages) {
			Path helpTopicDir = HelpBuildUtils.getHelpTopicDir(imageFile);

			writer.write("    <TR>\n");
			writer.write("        <TD>\n");
			writer.write("            ");

			String topicName = helpTopicDir.getFileName().toString();
			if (!topicName.equals(lastTopicName)) {
				lastTopicName = topicName;
				writer.write(topicName);
				writer.write('\n');
			}
			else {
				writer.write("&nbsp;\n");
			}

			writer.write("        </TD>\n");

			writer.write("        <TD>\n");
			writer.write("            ");
			writer.write(imageFile.getParent() + File.separator);
			writer.write("<font size=\"5\">");
			writer.write(imageFile.getFileName().toString());
			writer.write("</font>");
			writer.write('\n');
			writer.write("        </TD>\n");
			writer.write("    </TR>\n");
		}

		writer.write("</TABLE>\n");
		writer.write("</P>");

		writeFooter(writer);
	}

	private void generateUntestedImagesFile(File untestedOutputFile) {
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(untestedOutputFile));
			doGenerateUntestedImagesFile(writer);
		}
		catch (Exception e) {
			errorMessage("FAILED! writing untested images file", e);
		}
		finally {
			if (writer != null) {
				try {
					writer.close();
				}
				catch (IOException e1) {
					// don't care
				}
			}
		}
	}

	private void doGenerateUntestedImagesFile(BufferedWriter writer) throws IOException {
		writeHeader(writer);

		writer.write("<P>\n");
		writer.write("<TABLE BORDER=\"1\">\n");

		writer.write("    <TH>\n");
		writer.write("        Help Topic\n");
		writer.write("    </TH>\n");
		writer.write("    <TH>\n");
		writer.write("        Image Name\n");
		writer.write("    </TH>\n");

		Set<Entry<HelpTopic, Set<IMG>>> entrySet = untestedImages.entrySet();
		for (Entry<HelpTopic, Set<IMG>> entry : entrySet) {

			boolean printTopic = true;
			Set<IMG> set = entry.getValue();
			for (IMG img : set) {

				writer.write("    <TR>\n");
				writer.write("        <TD>\n");
				writer.write("            ");

				if (printTopic) {
					printTopic = false;
					writer.write(entry.getKey().getName());
				}
				else {
					writer.write("&nbsp;");
				}

				writer.write('\n');
				writer.write("        </TD>\n");

				writer.write("        <TD>\n");
				writer.write("            ");

				Path imageFile = img.getImageFile();
				writer.write(imageFile.getParent() + File.separator);
				writer.write("<font size=\"5\">");
				writer.write(imageFile.getFileName().toString());
				writer.write("</font>");
				writer.write('\n');
				writer.write("        </TD>\n");
				writer.write("    </TR>\n");
			}
		}

		writer.write("</TABLE>\n");
		writer.write("</P>\n");

		writeFooter(writer);
	}

	private Set<Path> getUnusedImages() {
		UnusedHelpImageFileFinder finder =
			new UnusedHelpImageFileFinder(helpDirectories, debugEnabled);
		return finder.getUnusedImages();
	}

	private void validateHelpImages() {
		debug("validating help images...");

		for (HelpModuleLocation helpDir : helpDirectories) {
			Collection<HelpTopic> topics = helpDir.getHelpTopics();
			for (HelpTopic topic : topics) {
				Collection<IMG> IMGs = topic.getAllIMGs();
				for (IMG img : IMGs) {
					Path imageFile = img.getImageFile();
					String imageName = imageFile.getFileName().toString();
					HelpTestCase testCase = imageNameToTestCase.get(imageName);
					if (testCase == null) {
						filterUntestedImage(topic, img);
					}
				}
			}
		}

		debug("Total untested images: " + untestedImages.size());
	}

	private void filterUntestedImage(HelpTopic topic, IMG img) {
		Path imageFile = img.getImageFile();
		if (examinedImageFiles.contains(imageFile)) {
			return; // already checked this image
		}
		examinedImageFiles.add(imageFile);

		// we don't wish to track small icons
		URL url;
		try {
			url = imageFile.toUri().toURL();

//			debug("Reading image: " + url);
			BufferedImage bufferedImage = ImageIO.read(url);
			int width = bufferedImage.getWidth();
			if (width <= 32) {
				return;
			}

			int height = bufferedImage.getHeight();
			if (height <= 32) {
				return;
			}

			// if the size is not enough, then we may just have to hard-code a 'known image list'
		}
		catch (MalformedURLException e) {
			errorMessage("Unable to read image: " + img, e);
		}
		catch (IndexOutOfBoundsException ioobe) {
			// happens for some of our invalid images
			errorMessage("Problem reading image (bad data?): " + img, ioobe);
			return;
		}
		catch (IOException e) {
			errorMessage("Unable to load image: " + img, e);
		}

		Set<IMG> set = untestedImages.get(topic);
		if (set == null) {
			set = new TreeSet<IMG>();
			untestedImages.put(topic, set);
		}

		set.add(img);
	}

	private void validateScreenShotTests() {
		debug("validating screen shots...");

		for (HelpTestCase testCase : testCases) {
			String imageName = testCase.getImageName();
			HelpTopic helpTopic = testCase.getHelpTopic();
			Collection<IMG> imgs = helpTopic.getAllIMGs();

			boolean foundImage = false;
			for (IMG img : imgs) {

				if (img.getImageFile().toAbsolutePath().toString().contains("shared")) {
					continue;  // skip images in the shared/images dir, they are not screen shots
				}

				Path imageFile = img.getImageFile();
				if (imageFile == null) {
					errorMessage("\n\nNo image file found for IMG tag: " + img + " in topic: " +
						helpTopic, null);
				}

				String imgName = imageFile.getFileName().toString();
				if (testCase.matches(imgName)) {
					foundImage = true;

					// there may be case issues in the test vs. the filename--prefer the filename
					imageName = imgName;
					break;
				}

			}

			if (!foundImage) {
				badlyNamedTestCases.add(testCase);
			}
			else {
				imageNameToTestCase.put(imageName, testCase);
			}
		}
	}

	private void parseScreenShots(String screenShotPaths) {
		debug("parsing help screenshots...");

		StringTokenizer tokenizer = new StringTokenizer(screenShotPaths, File.pathSeparator);
		while (tokenizer.hasMoreTokens()) {
			String path = tokenizer.nextToken();
			debug("\tparsing path entry: " + path);

			Path screenshotFile = Paths.get(path);
			String testName = screenshotFile.getFileName().toString();
			HelpTopic helpTopic = getHelpTopic(testName, screenshotFile);
			if (helpTopic == null) {
				continue;
			}

			HelpModuleLocation helpDir = helpTopic.getHelpDirectory();
			HelpTestFile testFile = new HelpTestFile(helpDir, helpTopic, screenshotFile, testName);
			Class<?> clazz = loadClass(screenshotFile);
			parseScreenShotTests(testFile, clazz);
		}

		debug("\tscreenshot test count: " + testCases.size());
	}

	private HelpTopic getHelpTopic(String testName, Path screenshotFile) {

		int index = testName.indexOf(SCREEN_SHOTS);
		String topicName = testName.substring(0, index);

		HelpTopic helpTopic = topicNameToTopic.get(topicName);
		if (helpTopic != null) {
			return helpTopic;
		}

		debug("Found file without a proper help topic name: " + topicName);

		// we make an exception for 'custom' test files
		int custom = testName.indexOf(CUSTOM_NAME);
		if (custom < 0) {
			// not custom
			badlyNamedTestFiles.add(testName);
			return null;
		}

		// note: the format for a custom screenshot name is FooCustomScreenShots, where Foo is the
		//       topic name
		topicName = testName.substring(0, custom);
		helpTopic = topicNameToTopic.get(topicName);
		if (helpTopic != null) {
			debug("\tit IS a custom screenshot; it is valid");
			return helpTopic;
		}

		// nope, it's bad
		badlyNamedTestFiles.add(testName);
		return null;
	}

	private void parseScreenShotTests(HelpTestFile testFile, Class<?> clazz) {
		Method[] methods = clazz.getDeclaredMethods();
		for (Method method : methods) {
			int modifiers = method.getModifiers();
			boolean isPublic = (Modifier.PUBLIC & modifiers) == Modifier.PUBLIC;
			if (!isPublic) {
				continue;
			}

			String name = method.getName();
			if (!name.startsWith(TEST)) {
				continue;
			}

			debug("\tfound test method: " + name);
			HelpTestCase helpTestCase = new HelpTestCase(testFile, name);
			testCases.add(helpTestCase);
		}
	}

	private Class<?> loadClass(Path testFile) {
		Path parent = testFile.getParent();
		String pathString = parent.toAbsolutePath().toString();
		int javaIndex = pathString.lastIndexOf(JAVA_DIR);

		String absolutePath = testFile.toAbsolutePath().toString();
		String packageAndClassName = absolutePath.substring(javaIndex + JAVA_DIR.length() + 1); // +1 for slash
		packageAndClassName = packageAndClassName.replaceAll("\\", ".");
		packageAndClassName = packageAndClassName.replaceAll("/", ".");
		String className = packageAndClassName.replace(".java", "");

		debug("Loading class: " + className);
		try {
			return Class.forName(className);
		}
		catch (ClassNotFoundException e) {
			errorMessage("Couldn't load class: " + className, e);
			e.printStackTrace();
			System.exit(1);
		}

		return null;
	}

	private void parseHelpDirectories(String helpModulePaths) {
		debug("parsing help directories...");

		StringTokenizer tokenizer = new StringTokenizer(helpModulePaths, File.pathSeparator);
		while (tokenizer.hasMoreTokens()) {
			String helpFilePath = tokenizer.nextToken();
			File directoryFile = new File(helpFilePath);
			if (!directoryFile.exists()) {
				debug("Help directory does not exist: " + directoryFile);
				continue;
			}

			HelpModuleLocation helpDir = new DirectoryHelpModuleLocation(directoryFile);
			helpDirectories.add(helpDir);

			Collection<HelpTopic> topics = helpDir.getHelpTopics();
			for (HelpTopic topic : topics) {
				topicNameToTopic.put(topic.getName(), topic);
			}
		}
	}

	private void debug(String string) {
		if (debugEnabled) {
			System.err.println("[" + HelpMissingScreenShotReportGenerator.class.getSimpleName() +
				"] " + string);
		}
	}

	private static void errorMessage(String message, Throwable t) {
		System.err.println("[" + GHelpBuilder.class.getSimpleName() + "] " + message);
		if (t != null) {
			t.printStackTrace();
		}
	}

	private void writeHeader(BufferedWriter writer) throws IOException {
		writer.write("<HTML>\n");
		writer.write("<HEAD>\n");
		createStyleSheet(writer);
		writer.write("</HEAD>\n");
		writer.write("<BODY>\n");
		writer.write("<H1>\n");
		writer.write("Ghidra Help Screen Shots Report");
		writer.write("</H1>\n");
	}

	private void writeFooter(BufferedWriter writer) throws IOException {

		writer.write("<BR>\n");
		writer.write("<BR>\n");

		writer.write("</BODY>\n");
		writer.write("</HTML>\n");
	}

	private void createStyleSheet(BufferedWriter writer) throws IOException {
		writer.write("<style>\n");
		writer.write("<!--\n");

		writer.write("body { font-family:arial; font-size:22pt }\n");
		writer.write("h1 { color:#000080; font-family:times new roman; font-size:28pt; font-weight:bold; text-align:center; }\n");
		writer.write("h2 { color:#984c4c; font-family:times new roman; font-size:28pt; font-weight:bold; }\n");
		writer.write("h2.title { color:#000080; font-family:times new roman; font-size:14pt; font-weight:bold; text-align:center;}\n");
		writer.write("h3 { color:#0000ff; font-family:times new roman; font-size:14pt; font-weight:bold; margin-left:.5in }\n");
		writer.write("table { margin-left:1in; margin-right:1in; min-width:20em; width:90%; background-color:#EEEEFF }\n");
		writer.write("th { text-align:center;  }\n");
		writer.write("td { text-align:left; padding: 20px }\n");

		writer.write("-->\n");
		writer.write("</style>\n");
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class HelpTestFile implements Comparable<HelpTestFile> {
		private String filename;
		private HelpModuleLocation helpDir;
		private Path filePath;
		private HelpTopic helpTopic;

		HelpTestFile(HelpModuleLocation helpDir, HelpTopic helpTopic, Path filePath, String filename) {
			this.helpDir = helpDir;
			this.helpTopic = helpTopic;
			this.filePath = filePath;
			this.filename = filename;
		}

		HelpTopic getHelpTopic() {
			return helpTopic;
		}

		@Override
		public int compareTo(HelpTestFile o) {
			int result = helpDir.getHelpLocation().compareTo(o.helpDir.getHelpLocation());
			if (result != 0) {
				return result;
			}
			return filename.compareTo(o.filename);
		}

		@Override
		public String toString() {
			return helpDir.getHelpLocation().getFileName() + " -> " + filename;
		}

	}

	private class HelpTestCase implements Comparable<HelpTestCase> {

		private HelpTestFile file;
		private String name;
		private String testMethodName;
		private String imageName;

		HelpTestCase(HelpTestFile file, String name) {
			this.file = file;
			this.name = name;

			if (!name.startsWith(TEST)) {
				throw new RuntimeException("Expecting test method name");
			}

			testMethodName = name;

			imageName = name.substring(TEST.length());

			if (imageName.startsWith(CAPTURE)) {
				imageName = imageName.substring(CAPTURE.length());
			}

// TODO for now, we expect the case to match; should we change all images to start with an upper case?
//			imageName = name.substring(TEST.length() + 1);
//			imageName = Character.toLowerCase(name.charAt(TEST.length() + 1)) + imageName;
			imageName = imageName + PNG_EXT;
		}

		boolean matches(String imgName) {
			if (imageName.equals(imgName)) {
				return true; // direct match!
			}

			return imageName.toLowerCase().equals(imgName.toLowerCase());
		}

		String getImageName() {
			return imageName;
		}

		String getTestName() {
			return testMethodName;
		}

		HelpTopic getHelpTopic() {
			return file.getHelpTopic();
		}

		@Override
		public int compareTo(HelpTestCase o) {
			int result = file.filename.compareTo(o.file.filename);
			if (result != 0) {
				return result;
			}

			return name.compareTo(o.name);
		}

		@Override
		public String toString() {
			return file + " " + name + "()";
		}
	}
}
