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
package ghidra.app.plugin.core.archive;

import java.awt.Component;
import java.awt.Font;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;

import generic.io.JarReader;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Class containing some methods for creating project files from a
 * Ghidra Version 1 archive file
 * that is input via the JarInputStream parameter. 
 */
class ProjectJarReader extends JarReader {

	private static final String PROJECT_FILE_SUFFIX = ProjectLocator.getProjectExtension();
	private static final String PROJECT_DIR_SUFFIX = ProjectLocator.getProjectDirExtension();
	private static final String XML_FILE_SUFFIX = ".xml";
	private static final String PROPERTIES_FILE_NAME = ".properties";
	private static final String ORIGINAL_PROPERTIES_FILE_NAME = "original" + PROPERTIES_FILE_NAME;
	private static final int READ_BLOCK_SIZE = 4096;

	/**
	 * Construct a new ProjectJarReader.
	 * @param jarIn the the jar file input stream the zip entries are
	 * read from.
	 */
	ProjectJarReader(JarInputStream jarIn) {
		super(jarIn);
	}

	private static final Pattern PROJECT_DATA_FILE_PATTERN = Pattern.compile(".+\\.rep/data(/.+)");

	private static String filterDataPathsOnly(String path) {
		path = path.replace('\\', '/');
		Matcher matcher = PROJECT_DATA_FILE_PATTERN.matcher(path);
		if (matcher.find()) {
			return matcher.group(1);
		}
		return null;
	}

	/**
	 * Writes the all zip entries from the jar input stream out to the specified
	 * project using the reader and any needed services from the service registry.
	 * 
	 * @param reader the reader for processing special files (entries).
	 * @param services the service registry
	 * @param project the project that the files are to be added to.
	 * @param monitor a task monitor for indicating progress to the user.
	 * 
	 * @return true if all files are successfully created.
	 */
	boolean createRecursively(XmlDataReader reader, File restoreDir, PluginTool tool,
			Project project, TaskMonitor monitor) throws IOException {
		boolean succeeded = true;
		StringBuffer errorBuf = new StringBuffer();

		List<String> xmlFiles = new ArrayList<>();

		boolean done = false;
		while (!done && succeeded) {
			if (monitor.isCancelled()) {
				return false;
			}
			try {
				//Get the zip entry.
				JarEntry entry = jarIn.getNextJarEntry();
				if (entry == null) {
					done = true;
					break;
				}
				String name = entry.getName();

				// discard property files
				if (name.endsWith(PropertyFile.PROPERTY_EXT) ||
					name.endsWith(ORIGINAL_PROPERTIES_FILE_NAME)) {
					continue;
				}

				name = filterDataPathsOnly(name);
				if (name == null) {
					continue;
				}

				File file = new File(restoreDir, name);
				FileUtilities.mkdirs(file.getParentFile());

				// Write it out to the file along with its data.
				FileOutputStream out = null;
				try {
					out = new FileOutputStream(file);
				}
				catch (FileNotFoundException fnfe) {
					String msg = fnfe.getMessage();
					if (msg == null) {
						msg = fnfe.toString();
					}
					Msg.showError(this, null, "Restore Failed",
						"Couldn't create file " + file.getAbsolutePath() + "\n" + msg);
					return false;
				}
				byte[] bytes = new byte[READ_BLOCK_SIZE];
				int numRead = 0;
				try {
					while ((numRead = jarIn.read(bytes)) != -1) {
						if (monitor.isCancelled()) {
							break;
						}
						out.write(bytes, 0, numRead);
					}
				}
				catch (IOException ioe) {
					succeeded = false;
					String msg = ioe.getMessage();
					if (msg == null) {
						msg = ioe.toString();
					}
					errorBuf.append(
						"Couldn't create file " + file.getAbsolutePath() + "\n" + msg + "\n");
					Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
				}
				finally {
					try {
						out.close();
					}
					catch (IOException ioe) {
						Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
					}
				}
				if (monitor.isCancelled()) {
					return false;
				}

				if (name.endsWith(XML_FILE_SUFFIX) &&
					!name.endsWith("projectDataTypes" + XML_FILE_SUFFIX)) {
					// the extra check is for backwards compatibility 
					xmlFiles.add(name);
				}

			}
			catch (IOException ioe) {
				succeeded = false;
				String msg = ioe.getMessage();
				if (msg == null) {
					msg = ioe.toString();
				}
				errorBuf.append("Failed to restore archive entry.\n" + msg + "\n");
				done = true;
				break;
			}
		}

		// Post-process the XML files that we created specially
		for (int i = 0; i < xmlFiles.size(); i++) {
			if (monitor.isCancelled()) {
				return false;
			}
			String relName = xmlFiles.get(i);
			try {
				if (!reader.addXMLObject(tool, restoreDir.getAbsolutePath(), relName, true,
					monitor) && !monitor.isCancelled()) {
					succeeded = false;
					errorBuf.append("Couldn't restore " + relName + ".\n" + "\n");
				}
			}
			catch (Exception e) {
				succeeded = false;
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				errorBuf.append("Couldn't restore " + relName + ".\n" + e.getMessage() + "\n");
			}
		}

		// Post-process the .property files to restore ghidra ownership.
//		for (int i = 0; i < propertyFiles.size(); i++) {
//			if (monitor.isCancelled()) {
//				return false;
//			}
//			String pName = propertyFiles.get(i);
//			if (!replacePropertyFile(basePath + pName)) {
//				succeeded = false;
//				errorBuf.append("Couldn't restore " + pName + ".\n" + "\n");
//			}
//		}

		if (monitor.isCancelled()) {
			return false;
		}

		final String summary = reader.getSummary();
		if (summary != null) {
			SystemUtilities.runSwingNow(
				() -> showErrorDialog(null, "Please review the messages below:", summary));
		}

		//TODO: Will still need to add code for changing actual file 
		//      ownership on the file system for the files that have been
		//      created on behalf of restoring other users' stuff.

		if (!succeeded) {
			String message = errorBuf.toString();
			String title = "Error Restoring Project Archive";
			project.releaseFiles(tool);
			Msg.showError(this, null, title, message);
		}
		return succeeded;
	}

	/**
	 * Displays an error dialog.
	 * 
	 * @param parent component to which dialog should be parented
	 * @param title  title of error dialog
	 * @param message  message(s) to display, can be multiple lines
	 */
	private static void showErrorDialog(Component parent, String title, String message) {
		if (message.indexOf("\n") >= 0) {
			showMultiLineMessage(parent, title, message, JOptionPane.ERROR_MESSAGE);
		}
		else {
			showSingleLineMessage(parent, title, message, JOptionPane.ERROR_MESSAGE);
		}
	}

	private static void showMultiLineMessage(Component parent, String title, String message,
			int type) {
		JTextArea textArea = new JTextArea(20, 60);
		textArea.setFont(new Font("Monospaced", Font.BOLD, 12));
		textArea.setEditable(false);
		textArea.setText(message);
		textArea.setOpaque(false);
		JScrollPane scrollPane = new JScrollPane(textArea);
		JOptionPane.showMessageDialog(parent, scrollPane, title, type);
	}

	private static void showSingleLineMessage(Component parent, String title, String message,
			int type) {
		JLabel textLabel = new JLabel();
		textLabel.setText(message);
		JOptionPane.showMessageDialog(parent, textLabel, title, type);
	}

	private boolean replacePropertyFile(String filepath) {
		if (!filepath.endsWith(ORIGINAL_PROPERTIES_FILE_NAME)) {
			return false;
		}
		File origFile = new File(filepath);
		int endOffset = filepath.length() - ORIGINAL_PROPERTIES_FILE_NAME.length();
		filepath = filepath.substring(0, endOffset) + PROPERTIES_FILE_NAME;

		File newFile = new File(filepath);
		if (newFile.exists() && !newFile.delete()) {
			return false;
		}

		// Need to rename the file from original.properties to .properties
		return origFile.renameTo(newFile);
	}

	private String modifyName(String name, String projectName) {
		// Project File?
		name = name.replace("\\", File.separator);
		if (name.endsWith(PROJECT_FILE_SUFFIX)) {
			int start = name.lastIndexOf(File.separator);
			if (start == -1) {
				return projectName + PROJECT_FILE_SUFFIX;
			}
			String first = name.substring(0, start);
			return first + projectName + PROJECT_FILE_SUFFIX;
		}
		// Project Folder?
		int suffixIndex = name.indexOf(PROJECT_DIR_SUFFIX);
		if (suffixIndex > -1) {
			String prefix = name.substring(0, suffixIndex);
			String suffix = name.substring(suffixIndex);
			int end = prefix.lastIndexOf(File.separator);
			if (end == -1) {
				return projectName + suffix;
			}
			return prefix.substring(0, end) + projectName + suffix;
		}
		return name;
	}
}
