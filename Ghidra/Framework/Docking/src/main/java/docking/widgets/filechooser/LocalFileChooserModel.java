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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import java.io.File;
import java.io.FileFilter;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.filechooser.FileSystemView;

import ghidra.util.filechooser.GhidraFileChooserModel;
import resources.ResourceManager;
import utility.function.Callback;

/**
 * A default implementation of the file chooser model that browses the local file system.
 * 
 */
public class LocalFileChooserModel implements GhidraFileChooserModel {
	private static final ImageIcon PROBLEM_FILE_ICON =
		ResourceManager.loadImage("images/unknown.gif");
	private static final ImageIcon PENDING_ROOT_ICON =
		ResourceManager.loadImage("images/famfamfam_silk_icons_v013/drive.png");

	private static final FileSystemRootInfo FS_ROOT_INFO = new FileSystemRootInfo();
	private static final FileSystemView FS_VIEW = FileSystemView.getFileSystemView();

	/**
	 * This is a cache of file icons, as returned from the OS's file icon service.
	 * <p>
	 * This cache is cleared each time a directory is requested (via 
	 * {@link #getListing(File, FileFilter)} so that any changes to a file's icon are visible the 
	 * next time the user hits refresh or navigates into a directory. 
	 */
	private Map<File, Icon> fileIconMap = new HashMap<>();

	private Callback callback;

	@Override
	public char getSeparator() {
		return File.separatorChar;
	}

	@Override
	public void setModelUpdateCallback(Callback callback) {
		this.callback = callback;
	}

	@Override
	public File getHomeDirectory() {
		return new File(System.getProperty("user.home"));
	}

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

	@Override
	public List<File> getRoots(boolean forceUpdate) {
		if (FS_ROOT_INFO.isEmpty() || forceUpdate) {
			FS_ROOT_INFO.updateRootInfo(callback);
		}
		return FS_ROOT_INFO.getRoots();
	}

	@Override
	public List<File> getListing(File directory, FileFilter filter) {
		// This clears the previously cached icons and avoids issues with modifying the map
		// while its being used by other methods by throwing away the instance and allocating
		// a new one.
		fileIconMap = new HashMap<>();

		if (directory == null) {
			return List.of();
		}
		File[] files = directory.listFiles(filter);
		return (files == null) ? List.of() : List.of(files);
	}

	@Override
	public Icon getIcon(File file) {
		if (FS_ROOT_INFO.isRoot(file)) {
			return FS_ROOT_INFO.getRootIcon(file);
		}
		Icon result = (file != null && file.exists())
				? fileIconMap.computeIfAbsent(file, this::getSystemIcon)
				: null;
		return (result != null) ? result : PROBLEM_FILE_ICON;
	}

	private Icon getSystemIcon(File file) {
		try {
			return FS_VIEW.getSystemIcon(file);
		}
		catch (Exception e) {
			// ignore, return null
		}
		return null;
	}

	@Override
	public String getDescription(File file) {
		if (FS_ROOT_INFO.isRoot(file)) {
			return FS_ROOT_INFO.getRootDescriptionString(file);
		}
		return FS_VIEW.getSystemTypeDescription(file);
	}

	@Override
	public boolean createDirectory(File directory, String name) {
		File newDir = new File(directory, name);
		return newDir.mkdir();
	}

	@Override
	public boolean isDirectory(File file) {
		return file != null && (FS_ROOT_INFO.isRoot(file) || file.isDirectory());
	}

	@Override
	public boolean isAbsolute(File file) {
		if (file != null) {
			return file.isAbsolute();
		}
		return false;
	}

	@Override
	public boolean renameFile(File src, File dest) {
		if (FS_ROOT_INFO.isRoot(src)) {
			return false;
		}
		return src.renameTo(dest);
	}

	//---------------------------------------------------------------------------------------------

	/**
	 * Handles querying / caching information about file system root locations.
	 * <p>
	 * Only a single instance of this class is needed and can be shared statically.
	 */
	private static class FileSystemRootInfo {
		private Map<File, String> descriptionMap = new ConcurrentHashMap<>();
		private Map<File, Icon> iconMap = new ConcurrentHashMap<>();
		private List<File> roots = List.of();
		private AtomicBoolean updatePending = new AtomicBoolean();

		synchronized boolean isEmpty() {
			return roots.isEmpty();
		}

		synchronized boolean isRoot(File f) {
			for (File root : roots) {
				if (root.equals(f)) {
					return true;
				}
			}
			return false;
		}

		/**
		 * Returns the currently known root locations.
		 * 
		 * @return list of currently known root locations
		 */
		synchronized List<File> getRoots() {
			return new ArrayList<>(roots);
		}

		Icon getRootIcon(File root) {
			return iconMap.get(root);
		}

		String getRootDescriptionString(File root) {
			return descriptionMap.get(root);
		}

		/**
		 * If there is no pending update, updates information about the root filesystem locations
		 * present on the local computer, in a partially blocking manner.  The initial list 
		 * of locations is queried directly, and the descriptions and icons for the root 
		 * locations are fetched in a background thread.
		 * <p>
		 * When new information is found during the background querying, the listener callback 
		 * will be executed so that it can cause UI updates.
		 * <p>
		 * If there is a pending background update, no-op.
		 *   
		 * @param callback callback
		 */
		void updateRootInfo(Callback callback) {
			if (updatePending.compareAndSet(false, true)) {
				File[] localRoots = listRoots(); // possibly sloooow
				synchronized (this) {
					roots = List.of(localRoots);
				}
				for (File root : localRoots) {
					descriptionMap.put(root, getInitialRootDescriptionString(root));
					iconMap.put(root, PENDING_ROOT_ICON);
				}

				Thread updateThread = new Thread(
					() -> asyncUpdateRootInfo(localRoots, Callback.dummyIfNull(callback)));
				updateThread.setName("GhidraFileChooser File System Updater");
				updateThread.start();
				// updateThread will unset the updatePending flag when done
			}
		}

		private File[] listRoots() {
			File[] tmpRoots = File.listRoots(); // possibly sloooow
			// File.listRoots javadoc says null result possible (but actual jdk code doesn't do it)
			return tmpRoots != null ? tmpRoots : new File[0];
		}

		private void asyncUpdateRootInfo(File[] localRoots, Callback callback) {
			try {
				// Populate root description strings with values that are hopefully faster to
				// get than the full description strings that will be fetched next.
				for (File root : localRoots) {
					String fastRootDescriptionString = getFastRootDescriptionString(root);
					if (fastRootDescriptionString != null) {
						descriptionMap.put(root, fastRootDescriptionString);
						callback.call();
					}
				}

				// Populate root description strings with final values, and icons
				for (File root : localRoots) {
					String slowRootDescriptionString = getSlowRootDescriptionString(root);
					if (slowRootDescriptionString != null) {
						descriptionMap.put(root, slowRootDescriptionString);
						callback.call();
					}

					Icon rootIcon = FS_VIEW.getSystemIcon(root); // possibly a slow call
					iconMap.put(root, rootIcon);
					callback.call();
				}
			}
			finally {
				updatePending.set(false);
			}
		}

		private String getInitialRootDescriptionString(File root) {
			return String.format("Unknown (%s)", formatRootPathForDisplay(root));
		}

		/**
		 * Return a description string for a file system root.  Avoid slow calls (such as 
		 * {@link FileSystemView#getSystemDisplayName(File)}.
		 * <p>
		 * @param root file location
		 * @return formatted description string, example "Local Drive (C:)" 
		 */
		private String getFastRootDescriptionString(File root) {
			try {
				String fsvSTD = FS_VIEW.getSystemTypeDescription(root);
				return String.format("%s (%s)", fsvSTD, formatRootPathForDisplay(root));
			}
			catch (Exception e) {
				//Windows expects the A drive to exist; if it does not exist, an exception results.
				//Ignore it.
			}
			return null;
		}

		/**
		 * Returns the string path of a file system root, formatted so it doesn't have a trailing
		 * backslash in the case of Windows root drive strings such as "c:\\", which becomes "c:"
		 * 
		 * @param root file location
		 * @return string path, formatted to not contain unneeded trailing slashes, example "C:"
		 *   instead of "C:\\"
		 */
		private String formatRootPathForDisplay(File root) {
			String s = root.getPath();
			return s.length() > 1 && s.endsWith("\\") ? s.substring(0, s.length() - 1) : s;
		}

		/**
		 * Return a description string for a root location.
		 * <p>
		 * @param root location to get description string
		 * @return string such as "Local Disk (C:)", "Network Drive (R:)"
		 */
		private String getSlowRootDescriptionString(File root) {
			// Special case the description of the root of a unix filesystem, otherwise it gets 
			// marked as removable 
			if ("/".equals(root.getPath())) {
				return "File system root (/)";
			}

			// Special case the description of floppies and removable disks, otherwise delegate to 
			// fsView's getSystemDisplayName.
			if (FS_VIEW.isFloppyDrive(root)) {
				return String.format("Floppy (%s)", formatRootPathForDisplay(root));
			}

			String fsvSTD = null;
			try {
				fsvSTD = FS_VIEW.getSystemTypeDescription(root);
			}
			catch (Exception e) {
				//Windows expects the A drive to exist; if it does not exist, an exception results.
				//Ignore it
			}
			if (fsvSTD == null || fsvSTD.toLowerCase().indexOf("removable") != -1) {
				return String.format("Removable Disk (%s)", formatRootPathForDisplay(root));
			}

			// call the (possibly slow) fsv's getSystemDisplayName
			return FS_VIEW.getSystemDisplayName(root);
		}
	}

}
