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
package docking.widgets.filechooser;

import java.io.File;
import java.io.FileFilter;
import java.util.HashMap;
import java.util.Map;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.filechooser.FileSystemView;

import ghidra.util.filechooser.GhidraFileChooserListener;
import ghidra.util.filechooser.GhidraFileChooserModel;
import resources.ResourceManager;

/**
 * A default implementation of the file chooser model
 * that browses the local file system.
 * 
 */
public class LocalFileChooserModel implements GhidraFileChooserModel {
	private static final ImageIcon PROBLEM_FILE_ICON =
		ResourceManager.loadImage("images/unknown.gif");

	private FileSystemView fsView = FileSystemView.getFileSystemView();
	private Map<File, String> rootDescripMap = new HashMap<>();
	private Map<File, Icon> rootIconMap = new HashMap<>();
	private File[] roots = new File[0];
	private GhidraFileChooserListener listener;

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getSeparator()
	 */
	@Override
	public char getSeparator() {
		return File.separatorChar;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#setListener(ghidra.util.filechooser.GhidraFileChooserListener)
	 */
	@Override
	public void setListener(GhidraFileChooserListener l) {
		this.listener = l;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getHomeDirectory()
	 */
	@Override
	public File getHomeDirectory() {
		return new File(System.getProperty("user.home"));
	}

	/**
	 * Probes for a "Desktop" directory under the user's home directory.
	 * <p>
	 * Returns null if the desktop directory is missing.
	 * <p>
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getDesktopDirectory()
	 */
	@Override
	public File getDesktopDirectory() {
		String userHomeProp = System.getProperty("user.home");
		if (userHomeProp == null) {
			return null;
		}

		File home = new File(userHomeProp);
		File desktop = new File(home, "Desktop");

		return desktop.isDirectory() ? desktop : null;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getRoots()
	 */
	@Override
	public File[] getRoots() {
		if (roots.length == 0) {
			roots = File.listRoots();

			// pre-populate root Description cache mapping with placeholder values that will be
			// overwritten by the background thread. 
			synchronized (rootDescripMap) {
				for (File r : roots) {
					rootDescripMap.put(r, getFastRootDescriptionString(r));
					rootIconMap.put(r, fsView.getSystemIcon(r));
				}
			}

			Thread backgroundRootScanThread = new FileDescriptionThread();
			backgroundRootScanThread.start();
		}
		return roots;
	}

	/**
	 * Return a description string for a file system root.  Avoid slow calls (such as {@link FileSystemView#getSystemDisplayName(File)}.
	 * <p>
	 * Used when pre-populating the root description map with values before {@link FileDescriptionThread background thread}
	 * finishes.  
	 */
	protected String getFastRootDescriptionString(File root) {
		String fsvSTD = "Unknown status";
		try {
			fsvSTD = fsView.getSystemTypeDescription(root);
		}
		catch (Exception e) {
			//Windows expects the A drive to exist; if it does not exist, an exception results.  Ignore it.
		}
		return String.format("%s (%s)", fsvSTD, formatRootPathForDisplay(root));
	}

	/**
	 * Return a description string for a root location.
	 * <p>
	 * Called from a {@link FileDescriptionThread background thread} to avoid blocking the UI
	 * while waiting for slow file systems. 
	 * <p>
	 * @param root
	 * @return string such as "Local Disk (C:)", "Network Drive (R:)"
	 */
	protected String getRootDescriptionString(File root) {
		// Special case the description of the root of a unix filesystem, otherwise it gets marked as removable 
		if ("/".equals(root.getAbsolutePath())) {
			return "File system root (/)";
		}

		// Special case the description of floppies and removable disks, otherwise delegate to fsView's getSystemDisplayName.
		if (fsView.isFloppyDrive(root)) {
			return String.format("Floppy (%s)", root.getAbsolutePath());
		}

		String fsvSTD = null;
		try {
			fsvSTD = fsView.getSystemTypeDescription(root);
		}
		catch (Exception e) {
			//Windows expects the A drive to exist; if it does not exist, an exception results.  Ignore it
		}
		if (fsvSTD == null || fsvSTD.toLowerCase().indexOf("removable") != -1) {
			return "Removable Disk (" + root.getAbsolutePath() + ")";
		}

		// call the (possibly slow) fsv's getSystemDisplayName
		return fsView.getSystemDisplayName(root);
	}

	/**
	 * Returns the string path of a file system root, formatted so it doesn't have a trailing backslash in the case
	 * of Windows root drive strings such as "c:\\", which becomes "c:"
	 */
	protected String formatRootPathForDisplay(File root) {
		String s = root.getAbsolutePath();
		return s.length() > 1 && s.endsWith("\\") ? s.substring(0, s.length() - 1) : s;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getListing(java.io.File, java.io.FileFilter)
	 */
	@Override
	public File[] getListing(File directory, final FileFilter filter) {
		if (directory == null) {
			return new File[0];
		}
		File[] files = directory.listFiles(filter);
		return (files == null) ? new File[0] : files;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getIcon(java.io.File)
	 */
	@Override
	public Icon getIcon(File file) {
		if (rootIconMap.containsKey(file)) {
			return rootIconMap.get(file);
		}
		if (file != null && file.exists()) {
			try {
				return fsView.getSystemIcon(file);
			}
			catch (Exception e) {
				// ignore, fall thru
			}
		}
		return PROBLEM_FILE_ICON;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#getDescription(java.io.File)
	 */
	@Override
	public String getDescription(File file) {
		synchronized (rootDescripMap) {
			if (rootDescripMap.containsKey(file)) {
				return rootDescripMap.get(file);
			}
		}
		return fsView.getSystemTypeDescription(file);
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#createDirectory(java.io.File, java.lang.String)
	 */
	@Override
	public boolean createDirectory(File directory, String name) {
		File newDir = new File(directory, name);
		return newDir.mkdir();
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#isDirectory(java.io.File)
	 */
	@Override
	public boolean isDirectory(File file) {
		File[] localRoots = getRoots();
		for (int i = 0; i < localRoots.length; i++) {
			if (localRoots[i].equals(file)) {
				return true;
			}
		}
		return file != null && file.isDirectory();
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#isAbsolute(java.io.File)
	 */
	@Override
	public boolean isAbsolute(File file) {
		if (file != null) {
			return file.isAbsolute();
		}
		return false;
	}

	/**
	 * @see ghidra.util.filechooser.GhidraFileChooserModel#renameFile(java.io.File, java.io.File)
	 */
	@Override
	public boolean renameFile(File src, File dest) {
		for (File root : roots) {
			if (root.equals(src)) {
				return false;
			}
		}
		return src.renameTo(dest);
	}

	private class FileDescriptionThread extends Thread {

		FileDescriptionThread() {
			super("File Chooser - File Description Thread");
		}

		@Override
		public void run() {
			synchronized (rootDescripMap) {
				for (File r : roots) {
					rootDescripMap.put(r, getRootDescriptionString(r));
				}
			}
			if (listener != null) {
				listener.modelChanged();
			}
		}
	}

}
