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
package utilities.util;

import java.awt.Desktop;
import java.io.*;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.FileSystem;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

import generic.jar.ResourceFile;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class FileUtilities {

	private final static int MAX_FILE_SIZE = 0x10000000;// 268Mb
	public final static int IO_BUFFER_SIZE = 32 * 1024;

	private static final ThreadLocal<NumberFormat> SIZE_FORMAT_THREAD_LOCAL =
		ThreadLocal.withInitial(() -> new DecimalFormat("#,###,###.##"));

	private static final FileFilter ACCEPT_ALL_FILE_FILTER = pathname -> true;

	private FileUtilities() {
		// utils class; can't create
	}

	/**
	 * Returns true if the give file is not null, exists, is a directory and contains files.
	 *
	 * @param directory the directory to test
	 * @return true if the give file is not null, exists, is a directory and contains files.
	 * @see #directoryIsEmpty(File)
	 */
	public static boolean directoryExistsAndIsNotEmpty(File directory) {
		if (directory == null) {
			return false;
		}

		if (!directory.exists()) {
			return false;
		}

		if (!directory.isDirectory()) {
			return false;
		}

		return !directoryIsEmpty(directory);
	}

	/**
	 * Returns true if the given file is not null, exits, is a directory and has no files.
	 *
	 * @param directory the directory to test for emptiness
	 * @return true if the given file is a directory and has not files.
	 */
	public static boolean directoryIsEmpty(File directory) {
		if (directory == null) {
			return true;
		}

		if (!directory.exists()) {
			return true;
		}

		if (!directory.isDirectory()) {
			return false;
		}

		File[] files = directory.listFiles();
		boolean hasFiles = files != null && files.length > 0;
		return !hasFiles;
	}

	/**
	 * Return an array of bytes read from the given file.
	 * @param sourceFile the source file
	 * @return the bytes
	 * @throws IOException if the file could not be accessed
	 */
	public final static byte[] getBytesFromFile(File sourceFile) throws IOException {
		return getBytesFromFile(new ResourceFile(sourceFile));
	}

	/**
	 * Return an array of bytes read from the sourceFile, starting at the
	 * given offset
	 * @param sourceFile file to read from
	 * @param offset offset into the file to begin reading
	 * @param length size of returned array of bytes
	 * @return array of bytes, size length
	 * @throws IOException thrown if there was a problem accessing the file or if there weren't
	 * at least {@code length} bytes read.
	 */
	public final static byte[] getBytesFromFile(File sourceFile, long offset, long length)
			throws IOException {
		return getBytesFromFile(new ResourceFile(sourceFile), offset, length);
	}

	/**
	 * Return an array of bytes read from the given file.
	 * @param sourceFile the source file
	 * @return the bytes
	 * @throws IOException if the file could not be accessed
	 */
	public final static byte[] getBytesFromFile(ResourceFile sourceFile) throws IOException {
		long fileLen = sourceFile.length();
		return getBytesFromFile(sourceFile, 0, fileLen);
	}

	/**
	 * Writes an array of bytes to a file.
	 * @param file the file to write to
	 * @param bytes the array of bytes to write
	 * @throws FileNotFoundException thrown if the file path is invalid
	 * @throws IOException thrown if the file can't be written to.
	 */
	public static void writeBytes(File file, byte[] bytes)
			throws FileNotFoundException, IOException {
		try (OutputStream os = new FileOutputStream(file)) {
			os.write(bytes);
		}
	}

	/**
	 * Return an array of bytes read from the sourceFile, starting at the
	 * given offset
	 * @param sourceFile file to read from
	 * @param offset offset into the file to begin reading
	 * @param length size of returned array of bytes
	 * @return array of bytes, size length
	 * @throws IOException thrown if there was a problem accessing the file or if there weren't
	 * at least {@code length} bytes read.
	 */
	public final static byte[] getBytesFromFile(ResourceFile sourceFile, long offset, long length)
			throws IOException {
		if (length > MAX_FILE_SIZE) {
			throw new IOException("File is too large: " + sourceFile.getName() +
				" file must be less than " + MAX_FILE_SIZE + " bytes");
		}
		if (offset < 0 || length < 0) {
			throw new IllegalArgumentException(
				"offset[" + offset + "] and length[" + length + "] must be greater than 0");
		}
		byte[] data = new byte[(int) length];

		try (InputStream fis = sourceFile.getInputStream()) {
			if (fis.skip(offset) != offset) {
				throw new IOException("Did not skip to the specified offset!");
			}
			int n = fis.read(data);
			if (n != length) {
				throw new IOException("Did not read expected number of bytes! Expected " + length +
					", but read " + n);
			}
			return data;
		}
	}

	/**
	 * Reads the bytes from the stream into a byte array
	 * @param is the input stream to read
	 * @return a byte[] containing the bytes from the stream.
	 * @throws IOException if an I/O error occurs reading
	 */
	public static byte[] getBytesFromStream(InputStream is) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] bytes = new byte[4096];
		int n;
		while ((n = is.read(bytes)) > 0) {
			baos.write(bytes, 0, n);
		}
		return baos.toByteArray();
	}

	/**
	 * Reads the number of bytes indicated by the expectedLength from the input stream and returns
	 * them in a byte array.
	 * @param inputStream the input stream
	 * @param expectedLength the number of bytes to be read
	 * @return an array of bytes, that is the expectedLength, that was read from the stream.
	 * @throws IOException if the "expectedLength" number of bytes can't be read from the input stream.
	 */
	public static byte[] getBytesFromStream(InputStream inputStream, int expectedLength)
			throws IOException {
		byte[] buf = new byte[expectedLength];
		int bufRemaining = expectedLength;

		int bytesCopied = 0;
		int bytesRead = 0;
		while (bufRemaining > 0 &&
			(bytesRead = inputStream.read(buf, bytesCopied, bufRemaining)) > 0) {
			bytesCopied += bytesRead;
			bufRemaining -= bytesRead;
		}

		if (bytesCopied != expectedLength) {
			throw new IOException("Could only read " + bytesCopied +
				" bytes from input stream when trying to read " + expectedLength + " bytes.");
		}

		return buf;
	}

	/**
	 * Copy the fromFile contents to the toFile.  The toFile will be overwritten or created.
	 *
	 * @param fromFile source file
	 * @param toFile destination file
	 * @param append if true and the file exists, the fromFile contents will be
	 * appended to the toFile.
	 * @param monitor if specified the progress will be reset and will advance to
	 * 100% when the copy is complete.
	 * @return number of bytes copied from source file to destination file
	 * @throws IOException thrown if there was a problem accessing the files
	 */
	public final static long copyFile(File fromFile, File toFile, boolean append,
			TaskMonitor monitor) throws IOException {

		try (FileInputStream fin = new FileInputStream(fromFile)) {
			if (monitor != null) {
				monitor.initialize((int) fromFile.length());
			}
			return copyStreamToFile(fin, toFile, append, monitor);
		}
	}

	/**
	 * Copy the fromFile contents to the toFile.
	 *
	 * @param fromFile source file
	 * @param toFile destination file
	 * @param append if true and the file exists, the fromFile contents will be
	 * 				 appended to the toFile.
	 * @param monitor if specified the progress will be reset and will advance to
	 * 				  100% when the copy is complete.
	 * @throws IOException thrown if there was a problem accessing the files
	 */
	public final static void copyFile(ResourceFile fromFile, File toFile, boolean append,
			TaskMonitor monitor) throws IOException {

		try (InputStream fin = fromFile.getInputStream()) {
			if (monitor != null) {
				monitor.initialize((int) fromFile.length());
			}
			copyStreamToFile(fin, toFile, append, monitor);
		}
	}

	/**
	 * Copy the fromFile contents to the toFile.  The toFile will be overwritten or created.
	 *
	 * @param fromFile source file
	 * @param toFile destination file
	 * @param monitor if specified the progress will be reset and will advance to
	 * 				  100% when the copy is complete.
	 * @throws IOException thrown if there was a problem accessing the files
	 */
	public final static void copyFile(ResourceFile fromFile, ResourceFile toFile,
			TaskMonitor monitor) throws IOException {

		try (InputStream fin = fromFile.getInputStream();
				OutputStream out = toFile.getOutputStream()) {

			if (monitor != null) {
				monitor.initialize((int) fromFile.length());
			}
			copyStreamToStream(fin, out, monitor);
		}
	}

	/**
	 * Ensures the specified leaf directory exists.
	 * <p>
	 * Does not create any missing parent directories.  See {@link #mkdirs(File)} instead.
	 * <p>
	 * Takes into account race conditions with external threads/processes
	 * creating the same directory at the same time.
	 * <p>
	 *
	 * @param dir The directory to create.
	 * @return True If the directory exists when this method completes; otherwise, false.
	 */
	public static boolean createDir(File dir) {
		if (dir.isDirectory()) {
			return true;
		}
		dir.mkdir();
		return dir.isDirectory();
	}

	/**
	 * Make all directories in the full directory path specified. This is a
	 * replacement for the File.mkdirs() which fails due to a problem with the
	 * File.exists() method with remote file systems on Windows. After renaming
	 * a directory, the exists() method frequently reports the old directory as
	 * still existing. In the case of File.mkdirs() the recreation of the old
	 * directory would fail. The File.mkdir() method does not perform this
	 * check.
	 *
	 * @param dir directory path to be created
	 * @return True If the directory exists when this method completes; otherwise, false.
	 */
	public static boolean mkdirs(File dir) {
		if (createDir(dir)) {
			return true;
		}
		File canonFile = null;
		try {
			canonFile = dir.getCanonicalFile();
		}
		catch (IOException e) {
			return false;
		}
		File parent = canonFile.getParentFile();
		return (parent != null) && (mkdirs(parent) && createDir(canonFile));
	}

	/**
	 * Ensures the specified leaf directory exists.
	 * <p>
	 * Throws an {@link IOException} if there is any problem while creating the directory.
	 * <p>
	 * Does not create any missing parent directories.  See {@link #checkedMkdirs(File)} instead.
	 * <p>
	 * Takes into account race conditions with external threads/processes
	 * creating the same directory at the same time.
	 * <p>
	 * @param dir The directory to create.
	 * @return a reference to the same {@link File} instance that was passed in.
	 * @throws IOException if there was a failure when creating the directory (ie. the
	 * parent directory did not exist or other issue).
	 */
	public static File checkedMkdir(File dir) throws IOException {
		if (!createDir(dir)) {
			throw new IOException("Failed to create directory " + dir);
		}
		return dir;
	}

	/**
	 * Ensures the specified full directory path exists, creating any missing
	 * directories as needed.
	 * <p>
	 * Throws an {@link IOException} if there is any problem while creating the directory.
	 * <p>
	 * Uses {@link #createDir(File)} to create new directories (which handles
	 * race conditions if other processes are also trying to create the same directory).
	 * <p>
	 *
	 * @param dir directory path to be created
	 * @return a reference to the same {@link File} instance that was passed in.
	 * @throws IOException if there was a failure when creating a directory.
	 */
	public static File checkedMkdirs(File dir) throws IOException {
		if (!createDir(dir)) {
			File canonFile = dir.getCanonicalFile();
			File parent = canonFile.getParentFile();
			if (parent != null) {
				checkedMkdirs(parent);
				checkedMkdir(canonFile);
			}
		}
		return dir;
	}

	/**
	 * Delete a file or directory and all of its contents
	 * 
	 * @param dir the directory to delete
	 * @return true if delete was successful. If false is returned, a partial
	 *         delete may have occurred.
	 */
	public static boolean deleteDir(Path dir) {
		return deleteDir(dir.toFile());
	}

	/**
	 * Delete a file or directory and all of its contents
	 *
	 * @param dir the dir to delete
	 * @return true if delete was successful. If false is returned, a partial
	 *         delete may have occurred.
	 */
	public final static boolean deleteDir(File dir) {
		try {
			return deleteDir(dir, TaskMonitor.DUMMY);
		}
		catch (CancelledException ce) {
			// can't happen due to our usage of the dummy monitor
		}
		return true;// can't get here
	}

	/**
	 * Delete a directory and all of its contents
	 *
	 * @param dir the dir to delete
	 * @param monitor the task monitor
	 * @return true if delete was successful. If false is returned, a partial
	 *         delete may have occurred.
	 * @throws CancelledException if the operation is cancelled
	 */
	public final static boolean deleteDir(File dir, TaskMonitor monitor) throws CancelledException {
		File[] files = dir.listFiles();
		if (files == null) {
			return dir.delete();
		}

		monitor.initialize(files.length);

		for (int i = 0; i < files.length; i++) {
			monitor.checkCanceled();
			if (files[i].isDirectory()) {
				// use a dummy monitor as not to ruin our progress
				if (!doDeleteDir(files[i], monitor)) {
					printDebug("Unable to delete directory: " + files[i]);
					return false;
				}
			}
			else {
				monitor.setMessage("Deleting file: " + files[i]);
				if (!files[i].delete()) {
					printDebug("Unable to delete file: " + files[i]);
					return false;
				}
			}
			monitor.incrementProgress(i);
		}

		return dir.delete();
	}

	/**
	 * A version of {@link #deleteDir(File,TaskMonitor)} that does not alter
	 * the progress value of the given monitor, only the status text.  This allows this recursive
	 * method to send status updates while the caller of this method controls the progress.
	 */
	private final static boolean doDeleteDir(File dir, TaskMonitor monitor)
			throws CancelledException {
		File[] files = dir.listFiles();

		if (files == null) {
			return dir.delete();
		}

		for (File file : files) {
			monitor.checkCanceled();
			if (file.isDirectory()) {
				// use a dummy monitor as not to ruin our progress
				if (!doDeleteDir(file, monitor)) {
					printDebug("Unable to delete directory: " + file);
					return false;
				}
			}
			else {
				monitor.setMessage("Deleting file: " + file);
				if (!file.delete()) {
					printDebug("Unable to delete file: " + file);
					return false;
				}
			}
		}
		return dir.delete();
	}

	/**
	 * This is the same as calling {@link #copyDir(File, File, FileFilter, TaskMonitor)} with
	 * a {@link FileFilter} that accepts all files.
	 * @param originalDir the source dir
	 * @param copyDir the destination dir
	 * @param monitor the task monitor
	 * @return the number of filed copied
	 * @throws IOException if there is an issue copying the files
	 * @throws CancelledException if the operation is cancelled
	 */
	public final static int copyDir(File originalDir, File copyDir, TaskMonitor monitor)
			throws IOException, CancelledException {
		return copyDir(originalDir, copyDir, ACCEPT_ALL_FILE_FILTER, monitor);
	}

	/**
	 * Copies the contents of <code>originalDir</code> to <code>copyDir</code>.  If the <code>originalDir</code>
	 * does not exist, then this method will do nothing.  If <code>copyDir</code> does not exist, then
	 * it will be created as necessary.
	 *
	 * @param originalDir The directory from which to extract contents
	 * @param copyDir The directory in which the extracted contents will be placed
	 * @param filter a filter to apply against the directory's contents
	 * @param monitor the task monitor
	 * @return the number of filed copied
	 * @throws IOException if there was a problem accessing the files
	 * @throws CancelledException if the copy is cancelled
	 */
	public final static int copyDir(File originalDir, File copyDir, FileFilter filter,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		if (!originalDir.exists()) {
			return 0;// nothing to do
		}

		File[] originalDirFiles = originalDir.listFiles(filter);
		if (originalDirFiles == null || originalDirFiles.length == 0) {
			return 0;// nothing to do
		}

		int copiedFilesCount = 0;
		monitor.initialize(originalDirFiles.length);

		for (File file : originalDirFiles) {
			monitor.checkCanceled();
			monitor.setMessage("Copying " + file.getAbsolutePath());
			File destinationFile = new File(copyDir, file.getName());
			if (file.isDirectory()) {
				copiedFilesCount += doCopyDir(file, destinationFile, filter, monitor);
			}
			else {
				destinationFile.getParentFile().mkdirs();

				// use a dummy monitor as not to ruin the progress
				copyFile(file, destinationFile, false, TaskMonitor.DUMMY);
				copiedFilesCount++;
			}
			monitor.incrementProgress(1);
		}

		return copiedFilesCount;
	}

	/**
	 * A version of {@link #copyDir(File, File, FileFilter, TaskMonitor)} that does not alter
	 * the progress value of the given monitor, only the status text.  This allows this recursive
	 * method to send status updates while the caller of this method controls the progress.
	 */
	private static int doCopyDir(File originalDir, File copyDir, FileFilter filter,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (!originalDir.exists()) {
			return 0;// nothing to do
		}

		File[] originalDirFiles = originalDir.listFiles(filter);
		if (originalDirFiles == null || originalDirFiles.length == 0) {
			return 0;// nothing to do
		}

		int copiedFilesCount = 0;
		for (File file : originalDirFiles) {
			monitor.checkCanceled();
			monitor.setMessage("Copying " + file.getAbsolutePath());
			File destinationFile = new File(copyDir, file.getName());
			if (file.isDirectory()) {
				copiedFilesCount += doCopyDir(file, destinationFile, filter, monitor);
			}
			else {
				destinationFile.getParentFile().mkdirs();

				// use a dummy monitor as not to ruin the progress
				copyFile(file, destinationFile, false, monitor);
				copiedFilesCount++;
			}
		}

		return copiedFilesCount;
	}

	private static void printDebug(String text) {
		boolean isProductionMode =
			!SystemUtilities.isInTestingMode() && !SystemUtilities.isInDevelopmentMode();
		if (isProductionMode) {
			return;// squash during production mode
		}

		Msg.debug(FileUtilities.class, text);
	}

	/**
	 * Copy the in stream to the toFile.  The toFile will be overwritten or created.
	 * @param in source input stream
	 * @param toFile destination file
	 * @param append if true and the file exists, the fromFile contents will be
	 * appended to the toFile.
	 * @param monitor if specified the progress will be reset and will advance to
	 * 100% when the copy is complete.
	 * @return number of bytes copied from source file to destination file
	 * @throws IOException thrown if there was a problem accessing the files
	 */
	public final static long copyStreamToFile(InputStream in, File toFile, boolean append,
			TaskMonitor monitor) throws IOException {

		try (OutputStream out = new FileOutputStream(toFile, append)) {
			return copyStreamToStream(in, out, monitor);
		}
	}

	/**
	 * Copy the contents of the specified fromFile to the out stream.
	 * @param fromFile file data source
	 * @param out destination stream
	 * @param monitor if specified the progress will be reset and will advance to
	 * 100% when the copy is complete.
	  * @throws IOException thrown if there was a problem accessing the files
	 */
	public final static void copyFileToStream(File fromFile, OutputStream out, TaskMonitor monitor)
			throws IOException {

		try (InputStream fin = new FileInputStream(fromFile)) {
			if (monitor != null) {
				monitor.initialize((int) fromFile.length());
			}
			copyStreamToStream(fin, out, monitor);
		}
	}

	/**
	 * Copy the <code>in</code> stream to the <code>out</code> stream.  The output stream will
	 * <b>not</b> be closed when the copy operation is finished.
	 *
	 * @param in source input stream
	 * @param out the destination output stream
	 * @param monitor if specified the progress will be reset and will advance to
	 * 				 100% when the copy is complete.
	 * @return the number of bytes copied from the input stream to the output stream.
	  * @throws IOException thrown if there was a problem accessing the files
	 */
	public static long copyStreamToStream(InputStream in, OutputStream out, TaskMonitor monitor)
			throws IOException {

		long totalBytesCopied = 0;
		byte[] buffer = new byte[IO_BUFFER_SIZE];
		if (monitor != null) {
			out = new MonitoredOutputStream(out, monitor);
		}

		// Copy file contents
		int bytesRead = 0;
		while ((bytesRead = in.read(buffer)) >= 0) {
			out.write(buffer, 0, bytesRead);
			totalBytesCopied += bytesRead;
		}
		out.flush();
		return totalBytesCopied;
	}

	/**
	 * Returns all of the lines in the file without any newline characters
	 * @param file The file to read in
	 * @return a list of file lines
	 * @throws IOException if an error occurs reading the file
	 */
	public static List<String> getLines(File file) throws IOException {
		return getLines(new ResourceFile(file));
	}

	/**
	 * Returns all of the lines in the file without any newline characters.
	 * <p>
	 * The file is treated as UTF-8 encoded.
	 * <p>
	 * @param file The text file to read in
	 * @return a list of file lines
	 * @throws IOException if an error occurs reading the file
	 */
	public static List<String> getLines(ResourceFile file) throws IOException {
		try (InputStream is = file.getInputStream()) {
			return getLines(is);
		}
		catch (FileNotFoundException exc) {
			return new ArrayList<>();
		}
	}

	/**
	 * Returns all of the lines in the file without any newline characters.  This method
	 * is the same as {@link #getLines(ResourceFile)}, except that it handles the exception
	 * that is thrown by that method.
	 *
	 * @param file The file to read in
	 * @return a list of file lines
	 */
	public static List<String> getLinesQuietly(ResourceFile file) {
		try {
			return getLines(file);
		}
		catch (IOException e) {
			Msg.error(FileUtilities.class, "Error parsing lines in file: " + file, e);
			return Collections.emptyList();
		}
	}

	/**
	 * Returns all of the lines in the BufferedReader without any newline characters.
	 * <p>
	 * The file is treated as UTF-8 encoded.
	 * <p>
	 * @param url the input stream from which to read
	 * @return a list of file lines
	 * @throws IOException thrown if there was a problem accessing the files
	 */
	public static List<String> getLines(URL url) throws IOException {

		try (InputStream is = url.openStream()) {
			return getLines(new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)));
		}
	}

	/**
	 * Returns all of the lines in the given {@link InputStream} without any newline characters.
	 * <p>
	 *
	 * @param is the input stream from which to read
	 * @return a {@link List} of strings representing the text lines of the file
	 * @throws IOException if there are any issues reading the file
	 */
	public static List<String> getLines(InputStream is) throws IOException {
		return getLines(new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)));
	}

	/**
	 * Returns all of the text in the given {@link InputStream}.
	 * <p>
	 * EOL characters are normalized to simple '\n's.
	 * <p>
	 * @param is the input stream from which to read
	 * @return the content as a String
	 * @throws IOException if there are any issues reading the file
	 */
	public static String getText(InputStream is) throws IOException {
		StringBuilder buf = new StringBuilder();
		List<String> lines = getLines(is);
		for (String string : lines) {
			buf.append(string);
			buf.append("\n");
		}
		return buf.toString();
	}

	/**
	 * Returns all of the text in the given {@link File}.
	 * <p>
	 * See {@link #getText(InputStream)}
	 * <p>
	 * @param f the file to read
	 * @return the content as a String
	 * @throws IOException if there are any issues reading the file or file is too large.
	 */
	public static String getText(File f) throws IOException {
		if (f.length() > MAX_FILE_SIZE) {
			throw new IOException("Text file too large to read: " + f + ", length: " + f.length());
		}
		try (InputStream is = new FileInputStream(f)) {
			return getText(is);
		}
	}

	/**
	 * Returns all of the lines in the {@link BufferedReader} without any newline characters.
	 *
	 * @param in BufferedReader to read lines from. The caller is responsible for closing the reader
	 * @return a {@link List} of strings representing the text lines of the file
	 * @throws IOException if there are any issues reading the file
	 */
	public static List<String> getLines(BufferedReader in) throws IOException {
		List<String> fileLines = new ArrayList<>();
		String line;
		while ((line = in.readLine()) != null) {
			fileLines.add(line);
		}
		return fileLines;
	}

	/**
	 * Writes the given list of Strings to the file, separating each by a newline character.
	 * <p>
	 * <b>
	 * This will overwrite the contents of the given file!
	 * </b>
	 * @param file the file to which the lines will be written
	 * @param lines the lines to write
	 * @throws IOException if there are any issues writing to the file
	 */
	public static void writeLinesToFile(File file, List<String> lines) throws IOException {
		try (FileWriter writer = new FileWriter(file)) {
			for (String string : lines) {
				writer.write(string);
				writer.write("\n");
			}
		}
	}

	/**
	 * Writes the given String to the specified {@link File}.
	 *
	 * @param file {@link File} to write to.
	 * @param s String to write to the file.
	 * @throws IOException if there were any issues while writing to the file.
	 */
	public static void writeStringToFile(File file, String s) throws IOException {
		try (FileWriter writer = new FileWriter(file)) {
			writer.write(s);
		}
	}

	/**
	 * Returns true if the given file:
	 * <ol>
	 *  <li> is <code>null</code>, or  </li>
	 * 	<li>{@link File#isFile()} is true, </li>
	 *  <li>and {@link File#length()} is == 0.</li>
	 *  </ol>
	 *
	 * @param f the file to check
	 * @return true if the file is not empty
	 */
	public static boolean isEmpty(File f) {
		if (f == null) {
			return true;
		}
		return f.isFile() && f.length() == 0;
	}

	/**
	 * Returns true if the given <code>potentialParentFile</code> is the parent path of
	 * the given <code>otherFile</code>, or if the two file paths point to the same path.
	 *
	 * @param potentialParentFile The file that may be the parent
	 * @param otherFile The file that may be the child
	 * @return boolean true if otherFile's path is within potentialParentFile's path.
	 */
	public static boolean isPathContainedWithin(File potentialParentFile, File otherFile) {
		try {
			String parentPath = potentialParentFile.getCanonicalPath().replace('\\', '/');
			String otherPath = otherFile.getCanonicalPath().replace('\\', '/');
			if (parentPath.equals(otherPath)) {
				return true;
			}

			if (!parentPath.endsWith("/")) {
				parentPath += "/";
			}

			return otherPath.startsWith(parentPath);
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Returns the portion of the second file that trails the full path of the first file.  If
	 * the paths are the same or unrelated, then null is returned.
	 *
	 * <P>For example, given, in this order, two files with these paths
	 *  <code>/a/b</code> and <code>/a/b/c</code>, this method will return 'c'.
	 *
	 * @param f1 the parent file
	 * @param f2 the child file
	 * @return the portion of the second file that trails the full path of the first file.
	 * @throws IOException if there is an error canonicalizing the path
	 */
	public static String relativizePath(File f1, File f2) throws IOException {
		String parentPath = f1.getCanonicalPath().replace('\\', '/');
		String otherPath = f2.getCanonicalPath().replace('\\', '/');
		if (parentPath.equals(otherPath)) {
			return null;
		}

		if (!parentPath.endsWith("/")) {
			parentPath += "/";
		}

		if (!otherPath.startsWith(parentPath)) {
			return null;
		}

		String childPath = otherPath.substring(parentPath.length());
		return childPath;
	}

	/**
	 * Return the relative path string of one resource file in another. If
	 * no path can be constructed or the files are the same, then null is returned.
	 * 
	 * Note: unlike {@link #relativizePath(File, File)}, this function does not resolve symbolic links.
	 *
	 * <P>For example, given, in this order, two files with these paths
	 *  <code>/a/b</code> and <code>/a/b/c</code>, this method will return 'c'.
	 *
	 * @param f1 the parent resource file
	 * @param f2 the child resource file
	 * @return the relative path of {@code f2} in {@code f1}
	 */
	public static String relativizePath(ResourceFile f1, ResourceFile f2) {
		StringBuilder sb = new StringBuilder(f2.getName());
		f2 = f2.getParentFile();
		while (f2 != null) {
			if (f1.equals(f2)) {
				return sb.toString();
			}
			sb.insert(0, f2.getName() + File.separator);
			f2 = f2.getParentFile();
		}
		return null;
	}

	public static boolean exists(URI uri) {

		String scheme = uri.getScheme();
		if ("file".equals(scheme)) {
			File file = new File(uri);
			return file.exists();
		}

		if (!"jar".equals(scheme)) {
			// don't know how to check
			return false;
		}

		FileSystem fs = getOrCreateJarFS(uri);
		if (fs == null) {
			return false;// error
		}
		Path path = Paths.get(uri);
		return Files.exists(path);
	}

	private static FileSystem getOrCreateJarFS(URI jarURI) {
		Map<String, String> env = new HashMap<>();
		try {
			return FileSystems.getFileSystem(jarURI);
		}
		catch (FileSystemNotFoundException e) {
			try {
				return FileSystems.newFileSystem(jarURI, env);
			}
			catch (IOException e1) {
				Msg.debug(FileUtilities.class, "Unexepecedly could not create jar filesystem");
				return null;
			}
		}
	}

	/**
	 * Returns true if a file exists on disk and has a case that matches the filesystem.
	 * This method is handy for
	 * comparing file paths provided externally (like from a user or a config file) to
	 * determine if the case of the file path matches the case of the file on the filesystem.
	 *
	 * @param file the file to be tested
	 * @return a result object that reports the status of the file
	 */
	public static FileResolutionResult existsAndIsCaseDependent(File file) {
		return existsAndIsCaseDependent(new ResourceFile(file));
	}

	/**
	 * Returns true if a file exists on disk and has a case that matches the filesystem.
	 * This method is handy for
	 * comparing file paths provided externally (like from a user or a config file) to
	 * determine if the case of the file path matches the case of the file on the filesystem.
	 *
	 * @param file the file to be tested
	 * @return a result object that reports the status of the file
	 */
	public static FileResolutionResult existsAndIsCaseDependent(ResourceFile file) {
		if (!file.exists()) {
			return FileResolutionResult.doesNotExist(file);
		}

		String canonicalPath;
		try {
			canonicalPath = file.getCanonicalPath();
		}
		catch (IOException e) {
			return FileResolutionResult.doesNotExist(file);
		}

		String absolutePath = file.getAbsolutePath();
		FileResolutionResult result = pathIsCaseDependent(canonicalPath, absolutePath);
		return result;
	}

	/*testing*/ static FileResolutionResult pathIsCaseDependent(String canonicalPath,
			String absolutePath) {

		List<String> canonical = pathToParts(canonicalPath);
		List<String> absolute = pathToParts(absolutePath);

		int cIndex = canonical.size() - 1;
		int aIndex = absolute.size() - 1;

		int size = aIndex;
		for (int i = size; i >= 0; i--) {
			String c = canonical.get(cIndex);
			String a = absolute.get(aIndex);

			if (c.equalsIgnoreCase(a)) {
				if (!c.equals(a)) {
					// different case
					return FileResolutionResult.notCaseDependent(canonicalPath, absolutePath);
				}

				cIndex--;
				aIndex--;
			}
			else {
				// move past relative path element (like '..')
				aIndex--;
			}
		}

		return FileResolutionResult.ok();
	}

	/**
	 * Ensures that the specified {@link File} param points to a file on the filesystem with a
	 * filename that has the exact same character case as the filename portion of the
	 * specified File.
	 * <p>
	 * This does not ensure that the path components are case-sensitive.
	 * <p>
	 * If the specified File and filesystem file do not match case a NULL is returned,
	 * otherwise the original File parameter is returned.
	 * <p>
	 * This method is useful on OS's that have filesystems that are case-insensitive and allow
	 * using File("A") to open real file "a", and you do not wish to allow this.
	 * <p>
	 * If the specified file being queried is a symbolic link to a file with a different name,
	 * no case sensitivity checks are done and the original specified File param is returned
	 * unchanged.
	 * <p>
	 * (Put another way: symlink "FILE1" -&gt; "../path/file2", no case sensitive enforcing can be done,
	 * but symlink "FILE1" -&gt; "../path/file1" will be enforced by this method.)
	 * <p>
	 * Querying a filepath that does not exist will result in a 'success' and the caller will
	 * receive the non-existent File instance back.
	 * <p>
	 * @param caseSensitiveFile {@link File} to enforce case-sensitive-ness of the name portion
	 * @return the same {@link File} instance if it points to a file on the filesystem with
	 * the same case, or a NULL if the case does not match.
	 */
	public static File resolveFileCaseSensitive(File caseSensitiveFile) {
		String canonicalName = null;
		try {
			File canonicalFile = caseSensitiveFile.getCanonicalFile();
			canonicalName = canonicalFile.getName();
		}
		catch (IOException ioe) {
			// The File had bad characters in the name that the Filesystem doesn't like.
			// Fall thru with null value, caller will get original File back as result
			// and they can deal with IOException errors when they try to use it.
		}

		String caseSensitiveName = caseSensitiveFile.getName();
		return (canonicalName != null) && canonicalName.equalsIgnoreCase(caseSensitiveName) &&
			!canonicalName.equals(caseSensitiveName) ? null : caseSensitiveFile;
	}

	/**
	 * Ensures the specified {@link File} points to a valid existing file,
	 * regardless of case match of the file's name.
	 * <p>
	 * Does not fixup any case-mismatching of the parent directories of the specified
	 * file.
	 * <p>
	 * If the exact filename already exists, it is returned unchanged, otherwise
	 * an all-lowercase version of the filename is probed, and then an all-uppercase
	 * version of the filename is probed, returning it if found.
	 * <p>
	 * Finally, the entire parent directory of the specified file is listed, and the first
	 * file that matches, case-insensitively to the target file, is returned.
	 * <p>
	 * If no file is found that matches, the original File instance is returned.
	 * <p>
	 * See also {@link #existsAndIsCaseDependent(ResourceFile)}.
	 * <p>
	 * @param f File instance
	 * @return File instance pointing to a case-insensitive match of the File parameter
	 */
	public static File resolveFileCaseInsensitive(File f) {
		if (f.exists()) {
			return f;
		}

		File fParent = f.getParentFile();
		String fName = f.getName();
		File tmp = new File(fParent, fName.toLowerCase());
		if (tmp.exists()) {
			return tmp;
		}
		tmp = new File(fParent, fName.toUpperCase());
		if (tmp.exists()) {
			return tmp;
		}

		File[] fileList = fParent.listFiles();
		if (fileList != null) {
			for (File otherFile : fileList) {
				if (otherFile.getName().equalsIgnoreCase(fName)) {
					return otherFile;
				}
			}
		}
		return f;
	}

	public static List<String> pathToParts(String path) {
		String[] parts = path.split("\\\\|/");
		List<String> list = new ArrayList<>(parts.length);
		for (String part : parts) {
			list.add(part);
		}
		return list;
	}

	/**
	 * Returns the size of the given file as a human readable String.
	 * <p>
	 * See {@link #formatLength(long)}
	 * <p>
	 *
	 * @param file the file for which to get size
	 * @return the pretty string
	 */
	public static String getPrettySize(File file) {
		return formatLength(file.length());
	}

	/**
	 * Returns a human readable string representing the length of something in bytes.
	 * <p>
	 * Larger sizes are represented in rounded off kilo and mega bytes.
	 * <p>
	 * TODO: why is the method using 1000 vs. 1024 for K?
	 *
	 * @param length the length to format
	 * @return pretty string - "1.1KB", "5.0MB"
	 */
	public static String formatLength(long length) {
		NumberFormat formatter = SIZE_FORMAT_THREAD_LOCAL.get();
		if (length < 1000) {
			return length + "B";
		}
		else if (length < 1000000) {
			return formatter.format((length / 1000f)) + "KB";
		}

		return formatter.format((length / 1000000f)) + "MB";
	}

	/**
	 * Creates a temporary directory using the given prefix
	 * @param prefix the prefix
	 * @return the temp file
	 */
	public static File createTempDirectory(String prefix) {
		try {
			File temp = File.createTempFile(prefix, Long.toString(System.currentTimeMillis()));
			if (!temp.delete()) {
				throw new IOException("Could not delete temp file: " + temp.getAbsolutePath());
			}
			if (!createDir(temp)) {
				throw new IOException("Could not create temp directory: " + temp.getAbsolutePath());
			}
			return temp;
		}
		catch (IOException e) {
			Msg.error(FileUtilities.class, "Error creating temporary directory", e);
		}

		return null;
	}

	/**
	 * Sets the given file (or directory) to readable and writable by only the owner.
	 *
	 * @param f The file (or directory) to set the permissions of.
	 */
	public static void setOwnerOnlyPermissions(File f) {
		// It's not clear from the below methods' documentation if you have to first
		// clear permissions for everyone before setting them for just the owner.
		// We'll do the (possibly) extra step though to ensure we get the behavior
		// we want.
		f.setReadable(false, false);
		f.setReadable(true, true);
		f.setWritable(false, false);
		f.setWritable(true, true);
	}

	/**
	 * Uses the {@link Desktop} API to open the specified file using the user's operating
	 * system's native widgets (ie. Windows File Explorer, Mac Finder, etc).
	 * <p>
	 * If the specified file is a directory, a file explorer will tend to be opened.
	 * <p>
	 * If the specified file is a file, the operating system will decide what to do based
	 * on the contents or name of the file.
	 * <p>
	 * If the {@link Desktop} API isn't support in the current env (unknown when
	 * this will actually happen) an error dialog will be displayed.
	 *
	 * @param file {@link File} ref to a directory or file on the local filesystem.
	 * @throws IOException if the OS doesn't know what to do with the file.
	 */
	public static void openNative(File file) throws IOException {
		if (!Desktop.isDesktopSupported()) {
			Msg.showError(FileUtilities.class, null, "Native Desktop Unsupported",
				"Access to the user's native desktop is not supported in the current environment." +
					"\nUnable to open file: " + file);
			return;
		}
		Desktop.getDesktop().open(file);
	}

	/**
	 * A convenience method to list the contents of the given directory path and pass each to the
	 * given consumer.  If the given path does not represent a directory, nothing will happen.
	 * 
	 * <p>This method handles closing resources by using the try-with-resources construct on 
	 * {@link Files#list(Path)}
	 * 
	 * @param path the directory
	 * @param consumer the consumer of each child in the given directory
	 * @throws IOException if there is any problem reading the directory contents
	 */
	public static void forEachFile(Path path, Consumer<Stream<Path>> consumer) throws IOException {

		if (!Files.isDirectory(path)) {
			return;
		}

		try (Stream<Path> pathStream = Files.list(path)) {
			consumer.accept(pathStream);
		}
	}
}
