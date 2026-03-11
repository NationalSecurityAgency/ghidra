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
package ghidra.app.plugin.processors.sleigh;

import static utilities.util.FileUtilities.*;

import java.io.*;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.antlr.runtime.RecognitionException;
import org.apache.commons.io.FilenameUtils;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.pcode.utils.SlaFormat;
import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slgh_compile.SleighCompileOptions;
import ghidra.sleigh.grammar.SleighPreprocessor;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.TimeoutException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileResolutionResult;
import utilities.util.FileUtilities;

/**
 * Represents a Sleigh .sla and .slaspec file, and a way to lock them to ensure exclusive access
 * while checking / updating the files.
 */
public class SleighLanguageFile {
	public static final String SLASPEC_EXT = ".slaspec";
	public static final String SLA_EXT = ".sla";

	/**
	 * Finds a sleigh language file, using search rules specific to sleigh.
	 * <p>
	 * If file is not found in the specific base directory, the entire app install will be searched
	 * for a matching file.
	 * 
	 * @param dir base directory where files are typically located 
	 * @param filename name of file, with or without the extension
	 * @param expectedExtension extension of the specific type of sleigh file, leading dot required.
	 *   Typically ".sla", ".slaspec", ".pspec", etc.
	 * @return ResourceFile that exists, never null
	 * @throws SleighFileException if file is not found or has bad case matching
	 */
	public static ResourceFile getLanguageResourceFile(ResourceFile dir, String filename,
			String expectedExtension) throws SleighFileException {
		ResourceFile f = findFile(dir, filename, expectedExtension);
		if (f == null) {
			f = new ResourceFile(dir, filename);
			throw new SleighFileException(
				"Missing sleigh file(%s): %s".formatted(expectedExtension, f.getAbsolutePath()));
		}

		FileResolutionResult result = existsAndIsCaseDependent(f);
		if (!result.isOk()) {
			throw new SleighFileException("Sleigh file %s is not properly case dependent: %s"
					.formatted(f.getAbsolutePath(), result.getMessage()));
		}
		return f;
	}

	/**
	 * Creates a {@link SleighLanguageFile} instance using the language directory and sla filename
	 * to bootstrap the information about the sla file, slaspec file and lock file.
	 * <p>
	 * NOTE: if the sla/slaspec are not found in the specified language directory, the entire 
	 * application will be searched for the slaspec.
	 * 
	 * @param dir {@link ResourceFile} language directory that should contain the sla or slaspec
	 *   file
	 * @param slaFilename name of the sla file (typically from the ldefs xml value), with optional
	 *   .sla file extension
	 * @return {@link SleighLanguageFile}, never null
	 * @throws SleighFileException if sla and slaspec file can not be found
	 */
	public static SleighLanguageFile fromSlaFilename(ResourceFile dir, String slaFilename)
			throws SleighFileException {
		String baseName = slaFilename.endsWith(SLA_EXT)
				? FilenameUtils.removeExtension(slaFilename)
				: slaFilename;

		ResourceFile slaSpecRFile;
		ResourceFile slaRFile;
		try {
			// find the slaspec and construct the sla filename from the slaspec's location
			slaSpecRFile = getLanguageResourceFile(dir, baseName + SLASPEC_EXT, SLASPEC_EXT);
			slaRFile = new ResourceFile(slaSpecRFile.getParentFile(),
				FilenameUtils.removeExtension(slaSpecRFile.getName()) + SLA_EXT);
		}
		catch (SleighFileException e) {
			try {
				// if slaspec is not found, fall back and search for .sla file.
				// if sla found, assume slaspec should be co-located there.
				// This results in a SleighLanguageFile instance that allows
				// the language description to be created, but the SleighLanguage
				// will fail to initialize because of the missing .slaspec
				slaRFile = getLanguageResourceFile(dir, baseName + SLA_EXT, SLA_EXT);
				slaSpecRFile = new ResourceFile(slaRFile.getParentFile(),
					FilenameUtils.removeExtension(slaRFile.getName()) + SLASPEC_EXT);
			}
			catch (SleighFileException e2) {
				throw e; // throw original exception, not this one
			}
		}
		if (slaSpecRFile.getFile(false) == null) {
			// single jar mode, no locking, no compiling of sla file possible

			if (!slaRFile.exists()) {
				throw new SleighFileException(
					"Missing sleigh sla file: " + slaRFile.getAbsolutePath());
			}
			return new SleighLanguageFile(slaRFile, slaSpecRFile, null);
		}

		File lockFile =
			new ResourceFile(slaRFile.getParentFile(), slaRFile.getName() + ".lock").getFile(false);

		return new SleighLanguageFile(slaRFile, slaSpecRFile, lockFile);
	}

	/**
	 * Creates a {@link SleighLanguageFile} instance using the language directory and Sleigh
	 * language file name to bootstrap the information about the slaspec file and lock file.
	 * <p>
	 * The .slaspec file will be found in the location indicated by the slaFilename.
	 * <p>
	 * The actual .sla file will be private to the user and located under the user's 
	 * .ghidra config directory. (or if single-jar mode, .sla will remain in the jar) 
	 * 
	 * @param dir {@link ResourceFile} language directory containing the slaspec file
	 * @param slaFilename name of the sla file (typically from the ldefs xml value), with optional
	 *   .sla file extension
	 * @return {@link SleighLanguageFile}, never null
	 * @throws SleighFileException if slaspec is not found
	 */
	public static SleighLanguageFile fromSlaFilename_UserDir(ResourceFile dir, String slaFilename)
			throws SleighFileException {

		String baseName = slaFilename.endsWith(SLA_EXT)
				? FilenameUtils.removeExtension(slaFilename)
				: slaFilename;

		ResourceFile slaSpecRFile =
			getLanguageResourceFile(dir, baseName + SLASPEC_EXT, SLASPEC_EXT);
		if (slaSpecRFile.getFile(false) == null) {
			// single jar mode, no locking, no compiling of sla file possible
			ResourceFile slaRFile = new ResourceFile(slaSpecRFile.getParentFile(),
				FilenameUtils.removeExtension(slaSpecRFile.getName()) + SLA_EXT);
			if (!slaRFile.exists()) {
				throw new SleighFileException(
					"Missing sleigh sla file: " + slaRFile.getAbsolutePath());
			}
			return new SleighLanguageFile(slaRFile, slaSpecRFile, null);
		}

		File sleighUserDir =
			new File(Application.getApplicationLayout().getUserSettingsDir(), "sleigh");
		if (!FileUtilities.mkdirs(sleighUserDir)) {
			throw new SleighFileException("Bad user settings /sleigh directory: " + sleighUserDir);
		}

		File slaFile = new File(sleighUserDir,
			FilenameUtils.removeExtension(slaSpecRFile.getName()) + SLA_EXT);

		File lockFile = new File(sleighUserDir, slaFile.getName() + ".lock");
		return new SleighLanguageFile(new ResourceFile(slaFile), slaSpecRFile, lockFile);
	}

	private final ResourceFile slaFile;
	private final ResourceFile slaSpecFile;
	private final File lockFile;

	private SleighLanguageFile(ResourceFile slaFile, ResourceFile slaSpecFile, File lockFile) {
		this.slaFile = slaFile;
		this.slaSpecFile = slaSpecFile;
		this.lockFile = lockFile;
	}

	/**
	 * Returns the path of this language's .sla file.
	 * 
	 * @return path of the .sla file
	 */
	public ResourceFile getSlaFile() {
		return slaFile;
	}

	/**
	 * Returns the path of the .slaspec file.
	 * 
	 * @return .slaspec file
	 */
	public ResourceFile getSlaSpecFile() {
		return slaSpecFile;
	}

	@Override
	public String toString() {
		return "%s -> %s".formatted(slaSpecFile.getAbsolutePath(), slaFile.getAbsolutePath());
	}

	/**
	 * Returns true if this language's files can be locked, or false if they can't be locked
	 * (embedded in a .jar file).
	 * 
	 * @return true if this language's files can be locked
	 */
	public boolean canLock() {
		return lockFile != null;
	}

	/**
	 * Executes a runnable while a lock file is being held.
	 * 
	 * @param <E> Exception type thrown by the runnable
	 * @param timeout maximum amount of time to wait to acquire the lock file.  This timeout does
	 *   not apply to the Runnable that is executed once the lock is acquired.
	 * @param monitor {@link TaskMonitor} that will be updated with lock file acquire attempt info
	 * @param r a runnable that can throw a SleighException
	 * @throws E if runnable throws E
	 * @throws IOException IO error acquiring the lock file 
	 * @throws TimeoutException if lock times out   
	 */
	<E extends Throwable> void withLock(Duration timeout, TaskMonitor monitor,
			CheckedRunnable<E> r) throws E, IOException, TimeoutException {

		if (lockFile == null) {
			throw new IOException("Unable to lock language, missing lock file");
		}

		long timeoutMS = timeout.toMillis();
		long startts = System.currentTimeMillis();
		long maxts = startts + timeoutMS;
		long sleepMS = Math.min(timeoutMS, 100); // 100ms is largest sleep-per-retry interval
		long lockerPid = -1;

		monitor.initialize(timeoutMS / 1000, "Locking Sleigh language file");
		monitor.setProgress(timeoutMS / 1000); // run the progress meter as count down from max to 0

		try (RandomAccessFile raf = new RandomAccessFile(lockFile, "rw")) {
			while (!monitor.isCancelled()) {
				// Lock an unused/non-existent portion of the file to avoid read/write errors
				// by other processes on Windows jvms
				try (FileLock lock = raf.getChannel().tryLock(LOCKFILE_LOCK_OFFSET, 1, false)) {
					if (lock != null) {
						writeLockerInfo(raf);
						r.run();
						raf.setLength(0);
						return;
					}
				}

				// failed to acquire lock, sleep and try again
				long remaining = maxts - System.currentTimeMillis();
				if (remaining < 0) {
					// failed to acquire lock within allowed time, give up
					break;
				}

				lockerPid = tryReadLockerInfo(raf);
				monitor.setMessage("Waiting on pid [%s] for Sleigh language file lock"
						.formatted(lockerPid != -1 ? Long.toString(lockerPid) : "unknown"));
				monitor.setProgress(remaining / 1000);

				Thread.sleep(sleepMS);
			}
			throw new TimeoutException(
				"Timeout when trying to lock Sleigh language file [%s], locker's pid: [%s]"
						.formatted(lockFile,
							lockerPid != -1 ? Long.toString(lockerPid) : "unknown"));
		}
		catch (IOException | InterruptedException e) {
			throw new IOException("Error locking Sleigh language file [%s]".formatted(lockFile), e);
		}
	}

	/**
	 * Checks if the sla file needs to be compiled/re-compiled.
	 * <p>
	 * Conditions: missing .sla, .sla is older than the .slaspec, or the sla format version value
	 * inside the existing .sla file does not match the current sla format version.
	 * <p>
	 * NOTE: this should only be called when holding the lock with 
	 * {@link #withLock(Duration, TaskMonitor, CheckedRunnable)}
	 * 
	 * @param requiredSlaFormatVersion required sla format version
	 * @return true if the .sla file needs to be compiled/recompiled
	 */
	public boolean needsCompilation(int requiredSlaFormatVersion) {
		return !slaFile.exists() || isSlaFileStale() || getSlaVersion() != requiredSlaFormatVersion;
	}

	/**
	 * Returns true if the slaspec file (or any included sinc files) is newer than the current
	 * sla file, indicating that the sla file should be recompiled.
	 * <p>
	 * Returns false if the slaspec or sla files are embedded in a jar (eg. single-jar mode).
	 * <p>
	 * NOTE: call this when holding the lock using {@link #withLock(Duration, TaskMonitor, CheckedRunnable)}
	 * 
	 * @return true if slaspec file is newer than the sla file
	 */
	public boolean isSlaFileStale() {
		// NOTE: SleighPreprocessor doesn't use ResourceFiles, so any 'include' directives processed
		// by it won't use ResourceFile.getFile()
		File f = slaSpecFile.getFile(false);
		if (f == null) {
			// if the slaspec file is embedded in a jar, always assume the sla file is correct
			return false;
		}
		long slaSpecLastMod;
		try {
			SleighPreprocessor preprocessor =
				new SleighPreprocessor(new ModuleDefinitionsAdapter(), f);
			slaSpecLastMod = preprocessor.scanForTimestamp();
		}
		catch (Exception e) {
			// slaSpecLastMod will be max_value which will force recompilation, error parsing 
			// will be handled elsewhere
			slaSpecLastMod = Long.MAX_VALUE;
		}
		long slaLastMod = slaFile.lastModified(); // will be 0 if does not exist
		return slaLastMod == 0 || slaSpecLastMod > slaLastMod;
	}

	/**
	 * Returns the format version number embedded in the compiled sla file.
	 * <p>
	 * NOTE: this should only be called when holding the lock with 
	 * {@link #withLock(Duration, TaskMonitor, CheckedRunnable)}
	 * 
	 * @return format version number embedded in the sla file, or -1 if error reading or 
	 * file doesn't exist
	 */
	public int getSlaVersion() {
		try (InputStream stream = slaFile.getInputStream()) {
			return SlaFormat.getSlaFormat(stream);
		}
		catch (Exception e) {
			return -1;
		}
	}

	/**
	 * Compiles the slaspec file and replaces the sla file with the newly compiled sleigh output.
	 * <p>
	 * NOTE: this should only be called when holding the lock with 
	 * {@link #withLock(Duration, TaskMonitor, CheckedRunnable)}
	 * 
	 * @param monitor {@link TaskMonitor}
	 * @throws SleighException if error occurs during compilation
	 */
	public void compileSlaFile(TaskMonitor monitor) throws SleighException {
		monitor.setMessage("Compiling Language File...");
		monitor.setIndeterminate(true);

		// see gradle/processorUtils.gradle for sleighArgs.txt generation
		String baseDir = FilenameUtils
				.separatorsToUnix(Application.getInstallationDirectory().getAbsolutePath());
		if (!baseDir.endsWith("/")) {
			baseDir += "/";
		}

		ResourceFile sleighArgsFile = getSleighArgsForSlaSpec(slaSpecFile);
		SleighCompileOptions compileOptions = sleighArgsFile != null && sleighArgsFile.exists()
				? SleighCompileOptions.fromFile(sleighArgsFile.getFile(true))
				: new SleighCompileOptions();

		compileOptions.addPreprocessorMacroDefinition("BaseDir", baseDir);

		File inputFile = slaSpecFile.getFile(true);

		File destFile = slaFile.getFile(true);
		long mypid = ProcessHandle.current().pid();
		File destTmpFile =
			new File(destFile.getParentFile(), destFile.getName() + ".%d.tmp".formatted(mypid));

		SleighCompile compiler = new SleighCompile();
		compiler.setOptions(compileOptions);

		try {
			int returnCode = compiler.run_compilation(inputFile.getPath(), destTmpFile.getPath());
			if (returnCode != 0) {
				destTmpFile.delete();
				throw new SleighException(
					"Errors compiling %s -- please check log messages for details"
							.formatted(slaSpecFile));
			}
			if (!destTmpFile.renameTo(destFile)) {
				// atomically renaming the tmp file to replace the existing dest file will 
				// succeed(linux)/fail(windows) depending on OS.
				// If it failed, manually remove the old file and then rename.
				// Because this is a non-atomic operation, its best to do this when holding a fs lock
				if (destFile.exists()) {
					checkedDelete(destFile);
				}
				checkedRename(destTmpFile, destFile);
			}
		}
		catch (IOException | RecognitionException e) {
			throw new SleighException("Error compiling %s".formatted(slaSpecFile), e);
		}
	}

	public interface CheckedRunnable<E extends Throwable> {
		void run() throws E;
	}

	private static void checkedDelete(File f) throws IOException {
		if (!f.delete()) {
			throw new IOException("Unable to delete previous file %s".formatted(f));
		}
	}

	private static void checkedRename(File srcFile, File destFile) throws IOException {
		if (!srcFile.renameTo(destFile)) {
			throw new IOException(
				"Failed to rename temp file [%s] to [%s]".formatted(srcFile, destFile));
		}
	}

	/**
	 * Offset in the lock file of where to place the lock so it doesn't interfere with
	 * reading the contents of the file from processes that don't have the lock (typically only
	 * an issue on windows).
	 */
	private static final int LOCKFILE_LOCK_OFFSET = 1_000_000;

	/**
	 * <pre>
	 * Raw:     .*(\/|\\)\.\.?(\/|\\)|\.(\/|\\)|\.\.(\/|\\)
	 * Parts:   .*(\/|\\)\.\.?(\/|\\) - optional text followed by a forward or back slash, 
	 *                                  followed by one or two literal dots, followed
	 *                                  by a forward or back slash
	 *      OR
	 *          \.(\/|\\)             - a literal dot followed by a forward or back slash
	 *      OR 
	 *          \.\.(\/|\\)           - two literal dots followed by a forward or back slash
	 * </pre>
	 */
	private static final Pattern RELATIVE_PATHS_PATTERN =
		Pattern.compile(".*(\\/|\\\\)\\.\\.?(\\/|\\\\)|\\.(\\/|\\\\)|\\.\\.(\\/|\\\\)");

	private static String discardRelativePath(String str) {
		return RELATIVE_PATHS_PATTERN.matcher(str).replaceFirst("");
	}

	private static void writeLockerInfo(RandomAccessFile raf) throws IOException {
		long mypid = ProcessHandle.current().pid();
		raf.setLength(0);
		raf.write("%d\n".formatted(mypid).getBytes(StandardCharsets.UTF_8));
	}

	private static long tryReadLockerInfo(RandomAccessFile raf) {
		try {
			byte[] buffer = new byte[64];
			raf.seek(0);
			int bytesRead = raf.read(buffer);
			if (bytesRead > 0 && buffer[bytesRead - 1] == '\n') {
				// low-tech verification of the data by checking for a trailing \n
				String s = new String(buffer, 0, bytesRead - 1, StandardCharsets.UTF_8);
				long lockersPid = Long.parseLong(s);
				return lockersPid;
			}
		}
		catch (IOException | NumberFormatException e) {
			// fall thru
		}
		return -1;
	}

	private static ResourceFile getSleighArgsForSlaSpec(ResourceFile slaSpecFile) {
		ResourceFile languageModule = Application.getModuleContainingResourceFile(slaSpecFile);
		if (languageModule == null) {
			return null;
		}
		return new ResourceFile(languageModule,
			SystemUtilities.isInReleaseMode() ? "data/sleighArgs.txt" : "build/tmp/sleighArgs.txt");
	}

	private static ResourceFile findFile(ResourceFile parentDir, String fileNameOrRelativePath,
			String extension) {
		ResourceFile file = new ResourceFile(parentDir, fileNameOrRelativePath).getCanonicalFile();
		if (file.exists()) {
			return file;
		}

		String fileName = FilenameUtils.getName(fileNameOrRelativePath);
		List<ResourceFile> files = findFiles(fileName, extension);
		if (files.size() == 1) {
			return files.get(0);
		}

		String relativePath = discardRelativePath(fileNameOrRelativePath);
		for (ResourceFile resourceFile : files) {
			if (file.getAbsolutePath().endsWith(relativePath)) {
				return resourceFile;
			}
		}
		return null;
	}

	private static List<ResourceFile> findFiles(String fileName, String extension) {
		List<ResourceFile> matches = new ArrayList<ResourceFile>();
		List<ResourceFile> files = Application.findFilesByExtensionInApplication(extension);
		for (ResourceFile resourceFile : files) {
			if (resourceFile.getName().equals(fileName)) {
				matches.add(resourceFile);
			}
		}
		return matches;
	}

}
