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
package resources;

import java.awt.Image;
import java.awt.MediaTracker;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import generic.Images;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import resources.icons.*;
import utility.module.ModuleUtilities;

/**
 * General resource management class that provides a convenient
 * way of accessing external resources used in Ghidra.
 * <p>
 * <a id="safe"></a>
 * There is a known problem with Java's {@link MediaTracker} that can cause deadlocks.  The various
 * methods of this class that create {@link ImageIcon}s will do so by loading image bytes directly,
 * as opposed to using the flawed constructor {@link ImageIcon#ImageIcon(Image)}.
 */
public class ResourceManager {

	private final static String DEFAULT_ICON_FILENAME = Images.BOMB;
	private static ImageIcon DEFAULT_ICON;
	private static Map<String, ImageIcon> iconMap = new HashMap<>();

	private static List<String> defaultSearchPaths;
	private static List<String> testSearchPaths;

	private static ClassLoader classLoader = ResourceManager.class.getClassLoader();

	/**
	 * Finds a resource with a given name. This method returns null if no
	 * resource with this name is found. The rules for searching resources
	 * associated with a given class are implemented by the defining class
	 * loader of the class.
	 * 
	 * @param filename "partially" qualified resource filename to get, e.g.,
	 *        "images/go-home.png" would look for the file named 'home.gif' in
	 *        the 'images' subdirectory of the 'resources' package,
	 *        following the search rules defined by your CLASSPATH and
	 *        return an InputStream if found; null if it cannot load the resource.
	 * @return the URL 
	 */
	public static URL getResource(String filename) {
		URL url = classLoader.getResource(filename);
		if (url != null) {
			return url;
		}

		url = getResource(getTestSearchPaths(), filename);
		return url;
	}

	/**
	 * Finds a resource with a given name. This method returns null if no resource
	 * with this name is found. The rules for searching resources associated with a
	 * given class are implemented by the defining class loader of the class.
	 *
	 * @param filename "partially" qualified resource filename to get, e.g., "images/home.gif" 
	 *        would look for the file named 'home.gif' in the 'images' subdirectory of 
	 *        the 'resources' package, following the search rules defined by your 
	 *        CLASSPATH and return an InputStream if found; null if it cannot load the resource.
	 * @return the input stream
	 */
	public static InputStream getResourceAsStream(String filename) {
		InputStream is = classLoader.getResourceAsStream(filename);
		if (is != null) {
			return is;
		}

		URL url = getResource(getTestSearchPaths(), filename);
		if (url == null) {
			return null;
		}

		try {
			return url.openStream();
		}
		catch (IOException e) {
			Msg.debug(RepaintManager.class, "Unable to open input stream for " + url, e);
			return null;
		}
	}

	/**
	 * Locates a File resource by the given name
	 * 
	 * @param filename the filename
	 * @return the File for the given resource; null if there is no such file
	 */
	public static File getResourceFile(String filename) {
		URL url = getResource(filename);
		if (url == null || !"file".equals(url.getProtocol())) {
			return null;
		}

		try {
			URI uri = new URI(url.toExternalForm());
			return new File(uri);
		}
		catch (URISyntaxException e) {
			throw new RuntimeException("Can not find resource " + filename);
		}
	}

	/**
	 * Searches the given set of directory paths for the given filename
	 * 
	 * @param searchPaths the paths 
	 * @param filename the filename
	 * @return the URL of the first matching file
	 */
	private static URL getResource(List<String> searchPaths, String filename) {

		for (String path : searchPaths) {
			File f = new File(path, filename);
			if (!f.exists()) {
				continue;
			}

			try {
				return f.toURI().toURL();
			}
			catch (MalformedURLException e) {
				Msg.debug(ResourceManager.class, "Unable to create URL for file", e);
			}
		}

		return null;
	}

	/**
	 * Search the classpath for files in the &lt;classpath entry&gt;/<code>dirName</code> 
	 * location that have the given extension.  In <code>null</code> is passed for the 
	 * extension, then all files found in the given dir names will be returned.  In this 
	 * way, <code>null</code> is a wildcard.
	 *
	 * <P>This method differs from {@link #getResource(String)} in that this method finds 
	 * multiple matches.
	 *
	 * @param dirName the name of the sub-directory under which to search
	 * @param extension the extension that matching files must possess
	 * @return set of URLs in the given directory that end with the given extension
	 */
	public static Set<URL> getResources(String dirName, String extension) {

		Set<String> names = doGetResourceNames(getDefaultSearchPaths(), dirName, extension);
		Set<String> testNames = doGetResourceNames(getTestSearchPaths(), dirName, extension);
		names.addAll(testNames);

		Set<URL> urls = names.stream().map(name -> getResource(name)).collect(Collectors.toSet());
		return urls;
	}

	/**
	 * Search the classpath for files in the &lt;classpath entry&gt;/<code>dirName</code> 
	 * location that have the given extension.  In <code>null</code> is passed for the 
	 * extension, then all files found in the given dir names will be returned.  In this 
	 * way, <code>null</code> is a wildcard.
	 *
	 * <P>The names returned from this method are relative and are meant to be used in a 
	 * later callback to this class for methods such as {@link #loadImage(String)} or
	 * {@link #getResource(String)}.
	 * 
	 *
	 * @param dirName the name of the directory under which to search
	 * @param extension the extension that matching files must possess
	 * @return set of filenames in the given directory that end with the given extension
	 */
	public static Set<String> getResourceNames(String dirName, String extension) {

		Set<String> resourceNames = doGetResourceNames(getDefaultSearchPaths(), dirName, extension);
		Set<String> testResourceNames =
			doGetResourceNames(getTestSearchPaths(), dirName, extension);

		resourceNames.addAll(testResourceNames);
		return resourceNames;
	}

	private static Set<String> doGetResourceNames(List<String> paths, String resourceDirName,
			String extension) {

		// check the system resource paths first
		Set<String> set = new HashSet<>();

		// now search the path entries
		for (String path : paths) {

			if (!StringUtils.endsWithAny(path.toLowerCase(), ".jar", ".zip")) {

				// maybe a directory	
				String classpathDirectoryEntry = path + File.separator + resourceDirName;
				File f = new File(classpathDirectoryEntry);
				findResources(set, f, resourceDirName, extension);
				continue;
			}

			// jar/zip
			File file = new File(path);
			try {
				if (file.exists()) {
					searchJarFile(set, file, resourceDirName, extension);
				}
			}
			catch (IOException e) {
				Msg.error(ResourceManager.class, "Unable to search compressed file", e);
			}
		}
		return set;
	}

	/**
	 * Search the directory for files ending in the given extension and add them to the list 
	 * that is returned
	 * 
	 * @param set the set to which resource names will be added
	 * @param file directory, e.g., "resources/defaultTools"
	 * @param dirName name of sub-directory, e.g. "defaultTools"
	 * @param extension file extension to look for
	 */
	private static void findResources(Set<String> set, File file, String dirName,
			String extension) {

		if (!file.exists()) {
			return;
		}

		String[] names = file.list();
		if (names == null) {
			return;
		}

		for (String element : names) {
			if (extension == null || element.endsWith(extension)) {
				set.add(dirName + "/" + element);
			}
		}
	}

	/**
	 * Search the given jar filename for files in 
	 * resources with the given file extension.
	 * @param set the set to which resource names will be added
	 * @param file jar or zip filename
	 * @param resourceDirName name of resource directory, e.g. "defaultTools"
	 * @param extension file extension to look for
	 */
	private static void searchJarFile(Set<String> set, File file, String resourceDirName,
			String extension) throws IOException {

		try (JarFile jarFile = new JarFile(file)) {
			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				JarEntry entry = entries.nextElement();
				if (entry.getSize() == 0) {
					continue;
				}

				String name = entry.getName();

				// the entry must match the pattern "resources/<resourceDirName>/xxx<extension> 
				// where extension may be null and 'xxx' is a filename and not another sub directory
				if (extension != null && !name.endsWith(extension)) {
					continue;
				}

				String startPath = resourceDirName;
				if (!name.startsWith(startPath)) {
					continue;
				}

				// is it a subdir?
				name = name.substring(startPath.length() + 1); // strip off valid path info
				File entryAsFile = new File(name);
				if (entryAsFile.getParent() != null) {
					continue; // the name was a subdir and not simply a file 
				}

				// add the entry; chop off "resources/"
				set.add(entry.getName());
			}
		}
	}

//==================================================================================================
// Icon Related Methods
//==================================================================================================	

	/**
	 * Creates a scaled ImageIcon from the given icon.
	 * 
	 * @param icon the icon to scale
	 * @param width the width of the new icon
	 * @param height the height of the new icon
	 * @param hints scaling hints (see {@link BufferedImage#getScaledInstance(int, int, int)}
	 * @return A new, scaled ImageIcon
	 */
	public static ImageIcon getScaledIcon(Icon icon, int width, int height, int hints) {
		return new ScaledImageIconWrapper(icon, width, height, hints);
	}

	/**
	 * Creates a scaled ImageIcon from the given icon with scaling of 
	 * {@link Image#SCALE_AREA_AVERAGING}
	 *  
	 * @param icon the icon to scale
	 * @param width the width of the new icon
	 * @param height the height of the new icon
	 * @return A new, scaled ImageIcon
	 */
	public static ImageIcon getScaledIcon(Icon icon, int width, int height) {
		return new ScaledImageIconWrapper(icon, width, height);
	}

	/**
	 * Get the disabled rendering of the given icon.
	 * @param icon The icon to disable.
	 * @return disabled icon
	 */
	public static ImageIcon getDisabledIcon(Icon icon) {
		return new DisabledImageIconWrapper(getImageIcon(icon));
	}

	/**
	 * Get the disabled rendering of the given imageIcon.
	 * @param icon The icon to disable.
	 * @return disabled icon
	 */
	public static ImageIcon getDisabledIcon(ImageIcon icon) {
		return new DisabledImageIconWrapper(icon);
	}

	/**
	 * Returns a disabled icon while allowing the caller to control the brightness of the icon
	 * returned
	 * 
	 * @param icon The icon to disable.
	 * @param brightnessPercent The level of brightness (0-100, where 100 is the brightest).
	 * @return a disabled version of the original icon.
	 */
	public static ImageIcon getDisabledIcon(Icon icon, int brightnessPercent) {
		return new DisabledImageIconWrapper(icon, brightnessPercent);
	}

	/**
	 * Creates an image icon from the given image.  This method will create an <code>ImageIcon</code>
	 * the <a href="safe">"safe"</a> way by avoiding the constructor 
	 * {@link ImageIcon#ImageIcon(Image)}, which can
	 * trigger problems with Java's {@link MediaTracker}.
	 * 
	 * @param imageName A textual description of the image; may be null
	 * @param image The image to use for creating an ImageIcon.
	 * @return the new icon
	 */
	public static ImageIcon getImageIconFromImage(String imageName, Image image) {
		return new ImageIconWrapper(image, imageName);
	}

	/**
	 * Returns an {@link ImageIcon} for the given icon.  If the value is already an ImageIcon, then
	 * that object is returned; otherwise, an ImageIcon will be created the <a href="#safe">safe</a>
	 * way.
	  
	 * @param icon The icon to convert
	 * @return the new icon
	 */
	public static ImageIcon getImageIcon(Icon icon) {
		if (icon instanceof ImageIcon) {
			return (ImageIcon) icon;
		}
		return new ImageIconWrapper(icon);
	}

	/**
	 * Get the name of this icon.  The value is usually going to be the URL from which the icon 
	 * was loaded
	 * 
	 * @param icon the icon for which the name is desired
	 * @return the name
	 */
	public static String getIconName(Icon icon) {
		String iconName = icon.toString();

		if (icon instanceof FileBasedIcon) {
			return ((FileBasedIcon) icon).getFilename();
		}
		if (icon instanceof ImageIcon) {
			iconName = ((ImageIcon) icon).getDescription();
		}

		/*
		 	TODO - not sure why we wanted just the name and not the entire URL?  Delete this 
		 	       after a bit
		 	
		if (iconName == null) {
			return null;
		}
		 	
		int pos = iconName.lastIndexOf(File.separator);
		if (pos >= 0) {
			iconName = iconName.substring(pos + 1);
		}
		else {
			pos = iconName.lastIndexOf("/");
			if (pos >= 0) {
				iconName = iconName.substring(pos + 1);
			}
		}
		*/
		return iconName;
	}

	/**
	 * Load the image using the specified bytes. The image icon will
	 * be cached using the image name. The bytes must have been
	 * read from an image file containing a supported image format,
	 * such as GIF, JPEG, or (as of 1.3) PNG.
	 * @param imageName   the name of the image
	 * @param imageBytes  the bytes of the image
	 * @return the image icon stored in the bytes
	 */
	public static ImageIcon loadImage(String imageName, byte[] imageBytes) {
		ImageIcon icon = iconMap.get(imageName);
		if (icon != null) {
			return icon;
		}
		icon = new ImageIconWrapper(imageBytes, imageName);
		iconMap.put(imageName, icon);
		return icon;
	}

	/**
	 * Load and scale the image specified by filename; returns null if problems occur trying to load
	 * the file.
	 * @param filename name of file to load, e.g., "images/home.gif"
	 * @param width - the width to scale the image to
	 * @param height - the height to scale the image to
	 * @return the scaled image.
	 */
	public static ImageIcon loadImage(String filename, int width, int height) {
		ImageIcon loadImage = loadImage(filename);
		if (loadImage == null) {
			return null;
		}
		return getScaledIcon(loadImage, width, height);
	}

	/**
	 * Load the image specified by filename; returns the default bomb icon
	 * if problems occur trying to load the file.
	 * <p>
	 * 
	 * @param filename name of file to load, e.g., "images/home.gif"
	 * @return the image icon stored in the bytes
	 */
	public static ImageIcon loadImage(String filename) {

		// use the wrapper so that images are not loaded until they are needed
		ImageIcon icon = iconMap.get(filename);
		if (icon != null) {
			return icon;
		}

		File imageFile = new File(filename);
		if (imageFile.exists()) {
			try {
				icon = new ImageIconWrapper(imageFile.toURI().toURL());
				iconMap.put(filename, icon);
				return icon;
			}
			catch (MalformedURLException e) {
				// handled below
			}
		}

		URL url = getResource(filename);
		if (url != null) {
			icon = new ImageIconWrapper(url);
			iconMap.put(filename, icon);
			return icon;
		}

		return getDefaultIcon();
	}

	/**
	 * Load the images specified by filenames; substitutes the default bomb icon
	 * if problems occur trying to load an individual file.
	 * <p>
	 * @param filenames vararg list of string filenames (ie. "images/home.gif")
	 * @return list of ImageIcons with each image, problem / missing images replaced with
	 * the default icon.
	 */
	public static List<ImageIcon> loadImages(String... filenames) {
		List<ImageIcon> results = new ArrayList<>(filenames.length);
		for (String filename : filenames) {
			results.add(loadImage(filename));
		}
		return results;
	}

	/**
	 * A convenience method to force the image denoted by <code>filename</code> to be read 
	 * from disk and to not use the cached version 
	 * 
	 * @param filename name of file to load, e.g., "images/home.gif"
	 * @return the image icon stored in the bytes
	 * @see #loadImage(String)
	 */
	public static ImageIcon reloadImage(String filename) {
		iconMap.remove(filename);
		return loadImage(filename);
	}

	public static ImageIcon getDefaultIcon() {
		if (DEFAULT_ICON == null) {
			URL url = getResource(DEFAULT_ICON_FILENAME);
			if (url == null) {
				Msg.error(ResourceManager.class,
					"Could not find default icon: " + DEFAULT_ICON_FILENAME);
			}
			DEFAULT_ICON = new ImageIconWrapper(url);
		}
		return DEFAULT_ICON;
	}

	public static Set<String> getToolImages() {
		Set<String> list = getResourceNames("defaultTools/images", null);
		filterImages(list);
		return list;
	}

	private static void filterImages(Set<String> set) {
		Iterator<String> it = set.iterator();
		while (it.hasNext()) {
			String filename = it.next().toLowerCase();
			if (!StringUtils.endsWithAny(filename, ".gif", ".jpg", ".png")) {
				it.remove();
			}
		}
	}

	private static synchronized List<String> getDefaultSearchPaths() {

		if (defaultSearchPaths != null) {
			return defaultSearchPaths;
		}

		List<String> results = new ArrayList<>();

		String classPath = System.getProperty("java.class.path");
		String java = System.getProperty("java.home");

		StringTokenizer st = new StringTokenizer(classPath, File.pathSeparator);
		while (st.hasMoreElements()) {
			String path = st.nextToken();
			if (path.startsWith(java)) {
				continue;
			}

			results.add(path);
		}

		defaultSearchPaths = results;
		return results;
	}

	/**
	 * Returns paths to search in test mode when finding resources. 
	 * 
	 * <P>This allows us to have our Eclipse development environment match the gradle test
	 * environment with respect to how resources are found.  Specifically, in Eclipse, resources
	 * are found on the classpath.  Further, in Eclipse, the 'test' and 'test.slow' folders are
	 * on the classpath.  Even more, Eclipse will include these test folders as transitive 
	 * dependencies for submodules.  Contrastingly, gradle will not include transitive <b>test</b>
	 * dependencies.  So, we add this code here so that we do not have to update each gradle
	 * build file that needs resources defined in a parent modules test resources.
	 * 
	 * @return the paths
	 */
	private static List<String> getTestSearchPaths() {

		if (testSearchPaths != null) {
			return testSearchPaths;
		}

		if (!SystemUtilities.isInTestingMode()) {
			testSearchPaths = Collections.emptyList();
			return testSearchPaths;
		}

		List<String> results = new ArrayList<>();
		List<String> searchPaths = getDefaultSearchPaths();

		// format: <repo>/Ghidra/Features/Base/build/classes/java/integrationTest
		for (String path : searchPaths) {

			Path modulePath = ModuleUtilities.getModule(path);
			if (modulePath == null) {
				continue; // not in a module
			}

			File moduleFile = modulePath.toFile();
			File file = new File(moduleFile, "src/test/resources");
			if (file.exists()) {
				results.add(file.getAbsolutePath());
			}

			file = new File(moduleFile, "src/test.slow/resources");
			if (file.exists()) {
				results.add(file.getAbsolutePath());
			}
		}

		testSearchPaths = results;
		return testSearchPaths;
	}
}
