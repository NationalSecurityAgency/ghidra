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
package ghidra.app.util.bin.format.dwarf.external;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Date;
import java.util.Objects;

import ghidra.app.util.bin.format.dwarf.external.DebugStreamProvider.StreamInfo;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
import utility.application.ApplicationUtilities;
import utility.application.XdgUtils;

/**
 * Provides debug files found in a debuginfod-client compatible directory structure.
 * <p>
 * Provides ability to store files.
 * <p>
 * Does not try to follow debuginfod's file age-off logic or config values.
 */
public class LocalDirDebugInfoDProvider implements DebugFileStorage {
	// static cache maint timing values.
	private static final long MAINT_INTERVAL_MS = Duration.ofDays(1).toMillis();
	public static final long MAX_FILE_AGE_MS = Duration.ofDays(7).toMillis();

	private static final String DEBUGINFOD_NAME_PREFIX = "debuginfod-dir://";
	public static final String GHIDRACACHE_NAME = "$DEFAULT";
	public static final String USERHOMECACHE_NAME = "$DEBUGINFOD_CLIENT_CACHE";

	/**
	 * Returns true if the specified name string specifies a LocalDirDebugInfoDProvider.
	 *  
	 * @param name string to test
	 * @return boolean true if name specifies a LocalDirDebugInfoDProvider
	 */
	public static boolean matches(String name) {
		return name.startsWith(DEBUGINFOD_NAME_PREFIX);
	}

	/**
	 * Creates a new {@link BuildIdDebugFileProvider} instance using the specified name string.
	 * 
	 * @param name string, earlier returned from {@link #getName()}
	 * @param context {@link DebugInfoProviderCreatorContext} to allow accessing information outside
	 * of the name string that might be needed to create a new instance
	 * @return new {@link BuildIdDebugFileProvider} instance
	 */
	public static LocalDirDebugInfoDProvider create(String name,
			DebugInfoProviderCreatorContext context) {
		name = name.substring(DEBUGINFOD_NAME_PREFIX.length());

		if (USERHOMECACHE_NAME.equals(name)) {
			return getUserHomeCacheInstance();
		}
		if (GHIDRACACHE_NAME.equals(name)) {
			return getGhidraCacheInstance();
		}

		return new LocalDirDebugInfoDProvider(new File(name));
	}

	/**
	 * {@return a new LocalDirDebugInfoDProvider that stores files in the same directory that the
	 * debuginfod-find CLI tool would (/home/user/.cache/debuginfod_client/)}
	 */
	public static LocalDirDebugInfoDProvider getUserHomeCacheInstance() {
		File cacheDir = new File(getCacheHomeLocation(), "debuginfod_client");
		return new LocalDirDebugInfoDProvider(cacheDir, DEBUGINFOD_NAME_PREFIX + USERHOMECACHE_NAME,
			"DebugInfoD Cache Dir <%s>".formatted(cacheDir));
	}

	/**
	 * {@return a new LocalDirDebugInfoDProvider that stores files in a Ghidra specific cache
	 * directory}
	 */
	public static LocalDirDebugInfoDProvider getGhidraCacheInstance() {
		File cacheDir = new File(Application.getUserCacheDirectory(), "debuginfo-cache");
		FileUtilities.mkdirs(cacheDir);
		LocalDirDebugInfoDProvider result = new LocalDirDebugInfoDProvider(cacheDir,
			DEBUGINFOD_NAME_PREFIX + GHIDRACACHE_NAME, "Ghidra Cache Dir <%s>".formatted(cacheDir));
		result.setNeedsMaintCheck(true);
		return result;
	}

	private final File rootDir;
	private final String name;
	private final String descriptiveName;
	private boolean needsInitMaintCheck;

	public LocalDirDebugInfoDProvider(File rootDir) {
		this(rootDir, DEBUGINFOD_NAME_PREFIX + rootDir.getPath(),
			rootDir.getPath() + " (debuginfod dir)");
	}

	public LocalDirDebugInfoDProvider(File rootDir, String name, String descriptiveName) {
		this.rootDir = rootDir;
		this.name = name;
		this.descriptiveName = descriptiveName;
	}

	public File getRootDir() {
		return rootDir;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getDescriptiveName() {
		return descriptiveName;
	}

	@Override
	public DebugInfoProviderStatus getStatus(TaskMonitor monitor) {
		return isValid() ? DebugInfoProviderStatus.VALID : DebugInfoProviderStatus.INVALID;
	}

	public File getDirectory() {
		return rootDir;
	}

	private boolean isValid() {
		return rootDir.isDirectory();
	}

	public void setNeedsMaintCheck(boolean needsInitMaintCheck) {
		this.needsInitMaintCheck = needsInitMaintCheck;
	}

	@Override
	public File getFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!isValid() || !debugInfo.hasBuildId()) {
			return null;
		}
		performInitMaintIfNeeded();

		File f = getCachePath(debugInfo);
		return f.isFile() ? f : null;
	}

	private File getBuildidDir(String buildId) {
		return new File(rootDir, buildId);
	}

	private File getCachePath(ExternalDebugInfo id) {
		String suffix = "";
		if (id.getObjectType() == ObjectType.SOURCE) {
			suffix = "-" + escapePath(Objects.requireNonNullElse(id.getExtra(), ""));
		}

		return new File(getBuildidDir(id.getBuildId()),
			id.getObjectType().getPathString() + suffix);
	}

	@Override
	public File putStream(ExternalDebugInfo id, StreamInfo stream, TaskMonitor monitor)
			throws IOException, CancelledException {
		assertValid();
		if (!id.hasBuildId()) {
			throw new IOException("Can't store debug file without BuildId value: " + id);
		}
		performInitMaintIfNeeded();

		File f = getCachePath(id);
		File tmpF = new File(f.getParent(), ".tmp_" + f.getName());
		FileUtilities.checkedMkdirs(f.getParentFile());
		try (stream; FileOutputStream fos = new FileOutputStream(tmpF)) {
			FSUtilities.streamCopy(stream.is(), fos, monitor);
		}
		try {
			if (f.isFile() && !f.delete()) {
				throw new IOException("Could not delete %s".formatted(f));
			}
			if (!tmpF.renameTo(f)) {
				throw new IOException("Could not rename temp file %s to %s".formatted(tmpF, f));
			}
		}
		finally {
			tmpF.delete(); // just blindly try to delete tmp file in case an exception was thrown
		}
		return f;
	}

	private void assertValid() throws IOException {
		if (!rootDir.isDirectory()) {
			throw new IOException("Invalid debuginfo directory: " + rootDir);
		}
	}

	@Override
	public String toString() {
		return String.format("LocalDebugInfoProvider [rootDir=%s, name=%s]", rootDir, name);
	}

	public void purgeAll() {
		cacheMaint(-1);
		File lastMaintFile = new File(rootDir, ".lastmaint");
		lastMaintFile.delete();
	}

	public void performInitMaintIfNeeded() {
		if (needsInitMaintCheck) {
			try {
				performCacheMaintIfNeeded();
			}
			finally {
				needsInitMaintCheck = false;
			}
		}
	}

	public void performCacheMaintIfNeeded() {
		if (!rootDir.isDirectory()) {
			return;
		}
		if (rootDir.getParentFile() == null) {
			// if someone gave us "/" as our path, don't try to delete files
			Msg.error(this, "Refusing to clean up files in " + rootDir);
			return;
		}

		long now = System.currentTimeMillis();
		File lastMaintFile = new File(rootDir, ".lastmaint");
		long lastMaintTS = lastMaintFile.isFile() ? lastMaintFile.lastModified() : 0;
		if (lastMaintTS + MAINT_INTERVAL_MS > now) {
			return;
		}

		cacheMaint(MAX_FILE_AGE_MS);

		try {
			Files.writeString(lastMaintFile.toPath(), "Last maint run at " + (new Date()));
		}
		catch (IOException e) {
			Msg.error(this, "Unable to write file cache maintenance file: " + lastMaintFile, e);
		}
	}

	/**
	 * Ages off debug files found in a compatible directory struct.
	 *  
	 * @param maxFileAgeMs max age of any debug file to allow, or -1 for all files
	 */
	private void cacheMaint(long maxFileAgeMs) {
		long cutoffMS =
			maxFileAgeMs >= 0 ? System.currentTimeMillis() - maxFileAgeMs : Long.MAX_VALUE;
		int deletedCount = 0;
		long deletedBytes = 0;

		for (File f : Objects.requireNonNullElse(rootDir.listFiles(), new File[0])) {
			if (f.isDirectory() && isBuildIdSubdirName(f.getName())) {
				int subDirFileCount = 0;
				int deletedSubDirFileCount = 0;
				for (File subF : Objects.requireNonNullElse(f.listFiles(), new File[0])) {
					subDirFileCount++;
					if (subF.isFile()) {
						long modified = subF.lastModified();
						if (modified != 0 && modified < cutoffMS) {
							long size = subF.length();
							if (subF.delete()) {
								deletedCount++;
								deletedBytes += size;
								deletedSubDirFileCount++;
							}
						}
					}
				}
				if (subDirFileCount == deletedSubDirFileCount) {
					// build-id hash directory should be empty, remove it
					if (!f.delete()) {
						Msg.warn(this, "Failed to delete empty debuginfod hash directory: " + f);
					}
				}
			}
		}
		Msg.debug(this,
			"Finished cache cleanup of debug files in %s, deleted %d files, %d total bytes"
					.formatted(rootDir, deletedCount, deletedBytes));
	}
	//---------------------------------------------------------------------------------------------

	/**
	 * Converts a path string into a string that can be used as a filename.
	 * <p>
	 * For example: "/usr/include/stdio.h" becomes "AABBCCDD-#usr#include#stdio.h", where
	 * AABCCDD is the hex value of the 32 bit hash of the original path string.
	 * (See {@link #djbX33AHash(String)}).
	 * 
	 * @param s path string
	 * @return escaped string
	 */
	private static String escapePath(String s) {
		// TODO: needs testing on how strings just barely longer than maxPath match with
		// the debuginfod-client.c logic
		int maxPath = 255 /* NAME_MAX*/ / 2; // from debuginfod-client.c:path_escape()
		int hash = (int) djbX33AHash(s);
		if (s.length() > maxPath) {
			int start = s.length() - maxPath; // keep trailing part of filepath
			s = s.substring(start);
		}
		s = s.replaceAll("[^a-zA-Z0-9._-]", "#"); // NOTE: the dash '-' needs to be last in the "[]" regex class
		return "%08x-%s".formatted(hash, s);
	}

	private static long djbX33AHash(String s) {
		// see debuginfod-client.c to ensure compatibility
		long hash = 5381;
		for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
			hash = ((hash << 5) + hash) + Byte.toUnsignedInt(b);
		}
		return hash;
	}

	private static boolean isBuildIdSubdirName(String s) {
		// subdirs under the debuginfod cache root should be simple 20 byte(ish) hash values.
		byte[] bytes = NumericUtilities.convertStringToBytes(s);
		return bytes != null && bytes.length >= 20 /* typical buildId hash size */;
	}

	private static File getCacheHomeLocation() {
		File cacheHomeDir = getEnvVarAsFile(XdgUtils.XDG_CACHE_HOME);
		if (cacheHomeDir == null) {
			try {
				cacheHomeDir = ApplicationUtilities.getJavaUserHomeDir();
			}
			catch (IOException e) {
				throw new RuntimeException("Missing home directory", e);
			}
			cacheHomeDir = new File(cacheHomeDir, XdgUtils.XDG_CACHE_HOME_DEFAULT_SUBDIRNAME);
		}
		return cacheHomeDir;
	}

	private static File getEnvVarAsFile(String name) {
		String path = System.getenv(name);
		if (path != null && !path.isBlank()) {
			File result = new File(path.trim());
			if (result.isAbsolute()) {
				return result;
			}
		}
		return null;
	}
}
