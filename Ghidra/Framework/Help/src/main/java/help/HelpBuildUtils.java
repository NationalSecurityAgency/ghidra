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
package help;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.text.MessageFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import help.validator.location.*;
import resources.IconProvider;
import resources.Icons;

public class HelpBuildUtils {

	private static final String HELP_TOPICS_ROOT_PATH = "help/topics";

	// Great. You've just summoned Cthulu.
	private static final Pattern HREF_PATTERN =
		Pattern.compile("\"(\\.\\./[^/.]+/[^/.]+\\.html*(#[^\"]+)*)\"", Pattern.CASE_INSENSITIVE);

	private static final Pattern STYLE_SHEET_PATTERN = Pattern.compile(
		"<link\\s+rel.+stylesheet.+href=\"*(.+(Frontpage.css))\"*.+>", Pattern.CASE_INSENSITIVE);

	private static final Pattern STYLE_CLASS_PATTERN =
		Pattern.compile("class\\s*=\\s*\"(\\w+)\"", Pattern.CASE_INSENSITIVE);

	private static final String STYLE_SHEET_FORMAT_STRING =
		"<link rel=\"stylesheet\" type=\"text/css\" href=\"{0}{1}{2}\">";
	private static final String SHARED_DIRECTORY = "shared/";

	public static boolean debug = true;

	private HelpBuildUtils() {
		// utils class; can't create
	}

	public static HelpModuleLocation toLocation(File file) {
		if (file.isDirectory()) {
			return new DirectoryHelpModuleLocation(file);
		}
		else if (file.isFile()) {
			return new JarHelpModuleLocation(file);
		}
		throw new IllegalArgumentException(
			"Don't know how to create a help module location for file: " + file);
	}

	public static Path getRoot(Collection<Path> roots, Path file) {
		for (Path dir : roots) {
			if (file.startsWith(dir)) {
				return dir;
			}
		}
		return null;
	}

	/**
	 * Returns a file object that is the help topic directory for the given file.  
	 * This method is useful for finding the help topic directory when the given 
	 * file doesn't live directly under a help topic.
	 */
	public static Path getHelpTopicDir(Path file) {
		Path helpTopics = file.getFileSystem().getPath("help", "topics");
		int last = file.getNameCount();
		for (int i = 0; i < last; i++) {
			Path sp = file.subpath(i, last);
			if (sp.startsWith(helpTopics)) {
				return file.subpath(0, i + 3); // 2 for help/topics, 1 for the actual topic
			}
		}
		return null;
	}

	public static Path getFile(Path srcFile, String relativePath) {
		if (relativePath == null || relativePath.isEmpty()) {
			return null;
		}

		if (relativePath.startsWith("/")) {
			return null; // absolute path
		}

		if (relativePath.contains(":")) {
			return null; // real URL
		}

		if (relativePath.contains("\\")) {
			return null; // not sure why this is here
		}

		Path parent = srcFile.getParent();
		return parent.resolve(relativePath);
	}

	public static Path relativizeWithHelpTopics(Path p) {
		if (p == null) {
			return null;
		}
		Path helpTopics = p.getFileSystem().getPath("help", "topics");
		return relativize(helpTopics, p);
	}

	public static Path relativize(Path parent, Path child) {
		if (child == null) {
			return null;
		}

		int last = child.getNameCount();
		for (int i = 0; i < last; i++) {
			Path sp = child.subpath(i, last);
			if (sp.startsWith(parent)) {
				return sp;
			}
		}
		return null;
	}

//==================================================================================================
// Cleanup Methods    
//==================================================================================================

	public static void cleanupHelpFileLinks(Path helpFile) throws IOException {
		String fixupHelpProperty = System.getProperty("fix.help.links");
		boolean cleanupHelpFiles = Boolean.parseBoolean(fixupHelpProperty);
		if (!cleanupHelpFiles) {
			return;
		}

		String fileContents = readFile(helpFile);
		String newContents = null; // this will be set if changes take place

		String linkFixupContents = fixLinksInFile(helpFile, fileContents);
		if (linkFixupContents != null) {
			newContents = linkFixupContents;

			// replace the input to future processing so we don't lose changes
			fileContents = newContents;
		}

		String styleSheetFixupContents = fixStyleSheetLinkInFile(helpFile, fileContents);
		if (styleSheetFixupContents != null) {
			// a fixup has taken place
			newContents = styleSheetFixupContents;

			// replace the input to future processing so we don't lose changes
			fileContents = newContents;
		}

		String styleSheetClassFixupContents = fixStyleSheetClassNames(helpFile, fileContents);
		if (styleSheetClassFixupContents != null) {
			newContents = styleSheetClassFixupContents;
		}

		if (newContents == null) {
			return; // nothing to write; no changes
		}

		writeFileContents(helpFile, newContents);
	}

	private static String fixStyleSheetLinkInFile(Path helpFile, String fileContents) {

		int currentPosition = 0;
		StringBuffer newContents = new StringBuffer();
		Matcher matcher = STYLE_SHEET_PATTERN.matcher(fileContents);

		boolean hasMatches = matcher.find();
		if (!hasMatches) {
			return null; // no work to do
		}

		// only care about the first hit, if there are multiple matches
		// Groups:
		// 0 - full match
		// 1 - href text with relative notation "../.."
		// 2 - href text without relative prefix

		int matchStart = matcher.start();
		String fullMatch = matcher.group(0);

		String beforeMatchString = fileContents.substring(currentPosition, matchStart);
		newContents.append(beforeMatchString);
		currentPosition = matchStart + fullMatch.length();

		String fullHREFText = matcher.group(1);
		if (fullHREFText.indexOf(SHARED_DIRECTORY) != -1) {
			return null; // already fixed; nothing to do
		}

		debug("Found stylesheet reference text: " + fullHREFText + " in file: " +
			helpFile.getFileName());

		// pull off the relative path structure
		String filenameOnlyHREFText = matcher.group(2);
		int filenameStart = fullHREFText.indexOf(filenameOnlyHREFText);
		String reltativePrefix = fullHREFText.substring(0, filenameStart);

		String updatedStyleSheetTag = MessageFormat.format(STYLE_SHEET_FORMAT_STRING,
			reltativePrefix, SHARED_DIRECTORY, filenameOnlyHREFText);
		debug("\tnew link tag: " + updatedStyleSheetTag);
		newContents.append(updatedStyleSheetTag);

		// grab the remaining content
		if (currentPosition < fileContents.length()) {
			newContents.append(fileContents.substring(currentPosition));
		}

		return newContents.toString();
	}

	private static String fixStyleSheetClassNames(Path helpFile, String fileContents) {

		int currentPosition = 0;
		StringBuffer newContents = new StringBuffer();
		Matcher matcher = STYLE_CLASS_PATTERN.matcher(fileContents);

		boolean hasMatches = matcher.find();
		if (!hasMatches) {
			return null; // no work to do
		}

		// only care about the first hit, if there are multiple matches
		// Groups:
		// 0 - full match
		// 1 - class name between quotes

		while (hasMatches) {

			int matchStart = matcher.start();
			String fullMatch = matcher.group(0);

			String beforeMatchString = fileContents.substring(currentPosition, matchStart);
			newContents.append(beforeMatchString);
			currentPosition = matchStart + fullMatch.length();

			String classNameText = matcher.group(1);
			if (!containsUpperCase(classNameText)) {
				// nothing to fixup; put the original contents back
				newContents.append(fullMatch);
			}
			else {
				debug("Found stylesheet class name text: " + classNameText + " in file: " +
					helpFile.getFileName());

				// pull off the relative path structure
				String updatedText = "class=\"" + classNameText.toLowerCase() + "\"";
				debug("\tnew link tag: " + updatedText);
				newContents.append(updatedText);
			}

			hasMatches = matcher.find();
		}

		// grab the remaining content
		if (currentPosition < fileContents.length()) {
			newContents.append(fileContents.substring(currentPosition));
		}

		return newContents.toString();
	}

	private static String fixLinksInFile(Path helpFile, String fileContents) {
		String updatedContents = fixRelativeLink(HREF_PATTERN, helpFile, fileContents);

		// not sure if more types to come
		return updatedContents;
	}

	private static String fixRelativeLink(Pattern pattern, Path helpFile, String fileContents) {
		int currentPosition = 0;
		StringBuffer newContents = new StringBuffer();
		Matcher matcher = pattern.matcher(fileContents);

		boolean hasMatches = matcher.find();
		if (!hasMatches) {
			return null; // no work to do
		}

		while (hasMatches) {
			int matchStart = matcher.start();
			String fullMatch = matcher.group(0);

			String beforeMatchString = fileContents.substring(currentPosition, matchStart);
			newContents.append(beforeMatchString);
			currentPosition = matchStart + fullMatch.length();

			String HREFText = matcher.group(1);
			debug("Found HREF text: " + HREFText + " in file: " + helpFile.getFileName());
			String updatedHREFText = resolveLink(HREFText);
			debug("\tnew link text: " + updatedHREFText);
			newContents.append('"').append(updatedHREFText).append('"');

			hasMatches = matcher.find();
		}

		// grab the remaining content
		if (currentPosition < fileContents.length()) {
			newContents.append(fileContents.substring(currentPosition));
		}

		return newContents.toString();
	}

	private static String resolveLink(String linkTextReference) {
		String helpTopicsPrefix = HELP_TOPICS_ROOT_PATH;
		if (linkTextReference.startsWith(helpTopicsPrefix)) {
			// this is what we prefer
			return linkTextReference;
		}

		String[] referenceParts = linkTextReference.split("/");
		if (referenceParts.length != 3) {
			return linkTextReference;
		}

		if (!referenceParts[0].equals("..")) {
			return linkTextReference;
		}

		return HELP_TOPICS_ROOT_PATH + "/" + referenceParts[1] + "/" + referenceParts[2];
	}

	private static String readFile(Path helpFile) throws IOException {
		InputStreamReader isr = new InputStreamReader(Files.newInputStream(helpFile));
		BufferedReader reader = new BufferedReader(isr);
		try {
			StringBuffer buffy = new StringBuffer();
			String line = null;
			while ((line = reader.readLine()) != null) {
				buffy.append(line).append('\n');
			}

			return buffy.toString();
		}
		finally {
			reader.close();
		}
	}

	private static void writeFileContents(Path helpFile, String updatedContents)
			throws IOException {
		OutputStreamWriter osw = new OutputStreamWriter(Files.newOutputStream(helpFile));
		BufferedWriter writer = new BufferedWriter(osw);
		try {
			writer.write(updatedContents);
		}
		finally {
			writer.close();
		}
	}

	public static void debug(String text) {
		if (debug) {
			System.err.println("[" + HelpBuildUtils.class.getSimpleName() + "] " + text);
		}
	}

	private static boolean containsUpperCase(String string) {
		for (int i = 0; i < string.length(); i++) {
			char charAt = string.charAt(i);
			if (Character.isUpperCase(charAt)) {
				return true;
			}
		}
		return false;
	}

	private static final Path DEFAULT_FS_ROOT;
	static {
		try {
			DEFAULT_FS_ROOT = Paths.get(".").toRealPath().getRoot();
		}
		catch (IOException e) {
			throw new RuntimeException(
				"Unexpected error finding root directory of local filesystem", e);
		}
	}

	private static Path toFSGivenRoot(Path root, Path path) {
		if (path.getNameCount() == 0) {
			if (path.isAbsolute()) {
				return root;
			}
			return root.relativize(root);
		}

		String first = path.getName(0).toString();
		String[] names = new String[path.getNameCount() - 1];
		for (int i = 0; i < names.length; i++) {
			names[i] = path.getName(i + 1).toString();
		}
		Path temp = root.getFileSystem().getPath(first, names);
		if (path.isAbsolute()) {
			return root.resolve(temp);
		}
		return temp;
	}

	public static Path toDefaultFS(Path path) {
		return toFSGivenRoot(DEFAULT_FS_ROOT, path);
	}

	public static Path toFS(Path targetFS, Path path) {
		return toFSGivenRoot(targetFS.toAbsolutePath().getRoot(), path);
	}

	public static Path createReferencePath(URI fileURI) {
		Path res;
		if (fileURI.getScheme() != null) {
			res = Paths.get(fileURI);
		}
		else {
			// res = new File(fileURI.getPath()).toPath();
			res = Paths.get(fileURI.getPath());
		}

		return res;
	}

	/**
	 * Returns true if the given String represents a remote resource
	 * 
	 * @param uriString the URI to test
	 * @return true if the given String represents a remote resource
	 */
	public static boolean isRemote(String uriString) {
		try {
			URI uri = new URI(uriString);
			return isRemote(uri);
		}
		catch (URISyntaxException e) {
			debug("Invalid URI: " + uriString);
			return false;
		}
	}

	/**
	 * Returns true if the given Path represents a remote resource
	 * 
	 * @param path the path
	 * @return true if the given Path represents a remote resource
	 */
	public static boolean isRemote(Path path) {
		if (path == null) {
			return false;
		}
		URI uri = path.toUri();
		return isRemote(uri);
	}

	/**
	 * Returns true if the given URI represents a remote resource
	 * 
	 * @param uri the URI
	 * @return true if the given URI represents a remote resource
	 */
	public static boolean isRemote(URI uri) {

		if (isFilesystemPath(uri)) {
			return false;
		}

		String scheme = uri.getScheme();
		if (scheme == null) {
			return false;
		}

		switch (scheme) {
			case "file":
				return false;
			case "jar":
				return false;
			default:
				break;
		}
		return true;
	}

	private static boolean isFilesystemPath(URI uri) {
		String scheme = uri.getScheme();
		if (scheme == null) {
			return true;
		}
		return scheme.equals("file");
	}

	private static URI resolve(Path sourceFile, String ref) throws URISyntaxException {
		URI resolved;
		if (ref.startsWith("help/topics")) {
			resolved = new URI(ref);  // help system syntax
		}
		else if (ref.startsWith("help/")) {
			resolved = new URI(ref);  // help system syntax
		}
		else {
			resolved = sourceFile.toUri().resolve(ref); // real link
		}

		return resolved;
	}

	private static Path toPath(URI uri) {
		try {
			return Paths.get(uri);
		}
		catch (FileSystemNotFoundException e) {
			try {
				FileSystems.newFileSystem(uri, Collections.emptyMap());
			}
			catch (IOException e1) {
				debug("Exception loading filesystem for uri: " + uri + "\n\t" + e1.getMessage());
			}
		}
		return Paths.get(uri);
	}

	/** 
	 * Turn an HTML IMG reference into a location object that has resolved path info.  This will 
	 * locate files based upon relative references, specialized help system references (i.e., 
	 * help/topics/...),  and absolute URLs.
	 * 
	 * @param sourceFile the source file path of the image reference
	 * @param ref the reference text
	 * @return an absolute path; null if the URI is remote
	 * @throws URISyntaxException 
	 */
	public static ImageLocation locateImageReference(Path sourceFile, String ref)
			throws URISyntaxException {

		if (Icons.isIconsReference(ref)) {

			// help system syntax: <img src="Icons.ERROR_ICON" />
			IconProvider iconProvider = Icons.getIconForIconsReference(ref);
			if (iconProvider == null || iconProvider.isInvalid()) {
				// bad icon name
				return ImageLocation.createInvalidRuntimeLocation(sourceFile, ref);
			}

			URL url = iconProvider.getUrl();
			URI resolved = null;
			Path path = null;
			if (url != null) { // we may have an icon with an invalid URL (e.g., a MultiIcon)
				resolved = url.toURI();
				path = toPath(resolved);
			}
			return ImageLocation.createRuntimeLocation(sourceFile, ref, resolved, path);
		}

		URI resolved = resolve(sourceFile, ref);
		if (isRemote(resolved)) {
			return ImageLocation.createRemoteLocation(sourceFile, ref, resolved);
		}

		Path path = createPathFromURI(sourceFile, resolved);
		return ImageLocation.createLocalLocation(sourceFile, ref, resolved, path);
	}

	/** 
	 * Turn an HTML HREF reference into an absolute path.  This will 
	 * locate files based upon relative references, specialized help system references (i.e., 
	 * help/topics/...),  and absolute URLs.
	 * 
	 * @param ref the reference text
	 * @return an absolute path; null if the URI is remote
	 * @throws URISyntaxException 
	 */
	public static Path locateReference(Path sourceFile, String ref) throws URISyntaxException {

		URI resolved = resolve(sourceFile, ref);
		if (isRemote(resolved)) {
			return null;
		}

		// non-remote/local path
		Path refPath = createPathFromURI(sourceFile, resolved);
		return refPath;
	}

	private static Path createPathFromURI(Path sourceFile, URI resolved) throws URISyntaxException {
		String scheme = resolved.getScheme();
		if (scheme == null) {
			// res = new File(fileURI.getPath()).toPath();
			return Paths.get(resolved.getRawPath());
		}

		if (scheme.startsWith("file")) {
			// bug?...we are sometimes handed a URI of the form 'file:/some/path', where the 
			// single '/' is not a valid file URI
			URI uri = new URI("file://" + resolved.getRawPath());
			return Paths.get(uri);
		}

		return Paths.get(resolved); // for now, allow non-local paths through to be handled later
		// throw new AssertException("Don't know how to handle path URI: " + sourceFile);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	public static interface Stringizer<T> {
		public String stringize(T obj);
	}

	public static class HelpFilesFilter implements FileFilter {

		private final String[] fileExtensions;

		public HelpFilesFilter(String... extensions) {
			this.fileExtensions = extensions;
		}

		@Override
		public boolean accept(File file) {
			String name = file.getName();
			if (file.isDirectory()) {
				if (".svn".equals(name) || "bin".equals(name) || "api".equals(name)) {
					return false;
				}
				return true;
			}

			for (String extension : fileExtensions) {
				if (name.endsWith(extension)) {
					return true;
				}
			}
			return false;
		}
	}
}
