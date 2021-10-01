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
package ghidra.formats.gfilesystem;

import java.awt.Component;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.io.FilenameUtils;

import docking.widgets.OptionDialog;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;
import utilities.util.FileUtilities;

public class FSUtilities {

	public static final String SEPARATOR_CHARS = "/\\:";
	public static final String SEPARATOR = "/";
	private static final char DOT = '.';
	private static final TimeZone GMT = TimeZone.getTimeZone("GMT");

	private static char[] hexdigit = "0123456789abcdef".toCharArray();

	/**
	 * Sorts GFiles by type (directories segregated from files) and then by name,
	 * case-insensitive.
	 */
	public static final Comparator<GFile> GFILE_NAME_TYPE_COMPARATOR = (o1, o2) -> {
		int result = Boolean.compare(!o1.isDirectory(), !o2.isDirectory());
		if (result == 0) {
			String n1 = Objects.requireNonNullElse(o1.getName(), "");
			String n2 = Objects.requireNonNullElse(o2.getName(), "");
			result = n1.compareToIgnoreCase(n2);
		}
		return result;
	};

	/**
	 * Converts a string-to-string mapping into a "key: value\n" multi-line string.
	 *
	 * @param info map of string key to string value.
	 * @return Multi-line string "key: value" string.
	 */
	public static String infoMapToString(Map<String, String> info) {
		StringBuilder sb = new StringBuilder();
		for (Entry<String, String> entry : info.entrySet()) {
			sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
		}

		return sb.toString();
	}

	/**
	 * Best-effort of sanitizing an untrusted string that will be used to create
	 * a file on the user's local filesystem.
	 *
	 * @param untrustedFilename filename string with possibly bad / hostile characters or sequences.
	 * @return sanitized filename
	 */
	public static String getSafeFilename(String untrustedFilename) {
		untrustedFilename = untrustedFilename.replaceAll("[/\\\\:|]", "_").trim();
		switch (untrustedFilename) {
			case "":
				return "empty_filename";
			case ".":
				return "dot";
			case "..":
				return "dotdot";
		}
		return escapeEncode(untrustedFilename);
	}

	/**
	 * Returns a copy of the input string with FSRL problematic[1] characters escaped
	 * as "%nn" sequences, where nn are hexdigits specifying the numeric ascii value
	 * of that character.
	 * <p>
	 * Characters that need more than a byte to encode will result in multiple "%nn" values
	 * that encode the necessary UTF8 codepoints.
	 * <p>
	 * [1] - non-ascii / unprintable / FSRL portion separation characters.
	 *
	 * @param s string, or null.
	 * @return string with problematic characters escaped as "%nn" sequences, or null
	 * if parameter was null.
	 */
	public static String escapeEncode(String s) {
		if (s == null) {
			return null;
		}

		String escapeChars = "%?|";
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c < 32 || c > 126 || escapeChars.indexOf(c) >= 0) {
				appendHexEncoded(sb, c);
			}
			else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * Returns a decoded version of the input stream where "%nn" escape sequences are
	 * replaced with their actual characters, using UTF-8 decoding rules.
	 * <p>
	 *
	 * @param s string with escape sequences in the form "%nn", or null.
	 * @return string with all escape sequences replaced with native characters, or null if
	 * original parameter was null.
	 * @throws MalformedURLException if bad escape sequence format.
	 */
	public static String escapeDecode(String s) throws MalformedURLException {
		if (s == null) {
			return null;
		}

		byte[] bytes = null;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length();) {
			char c = s.charAt(i);
			if (c == '%') {
				if (bytes == null) {
					bytes = new byte[(s.length() - i) / 3];
				}
				int pos = 0;

				while (((i + 2) < s.length()) && (c == '%')) {
					int v = Integer.parseInt(s.substring(i + 1, i + 3), 16);
					if (v < 0) {
						throw new MalformedURLException(
							"Bad hex characters in escape (%) pattern: " + s);
					}
					bytes[pos++] = (byte) v;
					i += 3;
					if (i < s.length()) {
						c = s.charAt(i);
					}
				}

				if ((i < s.length()) && (c == '%')) {
					throw new MalformedURLException("Bad escape pattern in " + s);
				}

				sb.append(new String(bytes, 0, pos, StandardCharsets.UTF_8));
			}
			else {
				sb.append(c);
				i++;
			}
		}
		return sb.toString();
	}

	private static void appendHexEncoded(StringBuilder sb, char c) {
		if (c < 0x80) {
			sb.append('%').append(hexdigit[c >> 4]).append(hexdigit[c & 0x0f]);
			return;
		}
		sb.append(URLEncoder.encode("" + c, StandardCharsets.UTF_8));
	}

	/**
	 * Returns a list of all files in a GFileSystem.
	 *
	 * @param fs {@link GFileSystem} to recursively query for all files.
	 * @param dir the {@link GFile} directory to recurse into
	 * @param result {@link List} of GFiles where the results are accumulated into, or null
	 * to allocate a new List, returned as the result.
	 * @param taskMonitor {@link TaskMonitor} that will be checked for cancel.
	 * @return {@link List} of accumulated {@code result}s
	 * @throws IOException if io error during listing of directories
	 * @throws CancelledException if user cancels
	 */
	public static List<GFile> listFileSystem(GFileSystem fs, GFile dir, List<GFile> result,
			TaskMonitor taskMonitor) throws IOException, CancelledException {
		if (result == null) {
			result = new ArrayList<>();
		}

		for (GFile gFile : fs.getListing(dir)) {
			taskMonitor.checkCanceled();
			if (gFile.isDirectory()) {
				listFileSystem(fs, gFile, result, taskMonitor);
			}
			else {
				result.add(gFile);
			}
		}
		return result;
	}

	/**
	 * Returns the type value of the {@link FileSystemInfo} annotation attached to the
	 * specified class.
	 *
	 * @param clazz Class to query.
	 * @return File system type string.
	 */
	public static String getFilesystemTypeFromClass(Class<?> clazz) {
		FileSystemInfo fsi = clazz.getAnnotation(FileSystemInfo.class);
		return fsi != null ? fsi.type() : null;
	}

	/**
	 * Returns the description value of the {@link FileSystemInfo} annotation attached to the
	 * specified class.
	 *
	 * @param clazz Class to query.
	 * @return File system description string.
	 */
	public static String getFilesystemDescriptionFromClass(Class<?> clazz) {
		FileSystemInfo fsi = clazz.getAnnotation(FileSystemInfo.class);
		return fsi != null ? fsi.description() : null;
	}

	/**
	 * Returns the priority value of the {@link FileSystemInfo} annotation attached to the
	 * specified class.
	 *
	 * @param clazz Class to query.
	 * @return File system priority integer.
	 */
	public static int getFilesystemPriorityFromClass(Class<?> clazz) {
		FileSystemInfo fsi = clazz.getAnnotation(FileSystemInfo.class);
		return fsi != null ? fsi.priority() : FileSystemInfo.PRIORITY_DEFAULT;
	}

	/**
	 * Returns true if all the {@link FSRL}s in the specified list are from the filesystem.
	 *
	 * @param fsrls {@link List} of {@link FSRL}s.
	 * @return boolean true if all are from same filesystem.
	 */
	public static boolean isSameFS(List<FSRL> fsrls) {
		if (fsrls.isEmpty()) {
			return true;
		}
		FSRLRoot fsFSRL = fsrls.get(0).getFS();
		for (FSRL fsrl : fsrls) {
			if (!fsFSRL.equals(fsrl.getFS())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Displays a filesystem related {@link Throwable exception} in the most user-friendly manner
	 * possible, even if we have to do some hacky things with helping the user with
	 * crypto problems.
	 * <p>
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param parent
	 *            a parent component used to center the dialog (or null if you
	 *            don't have one)
	 * @param title
	 *            the title of the pop-up dialog (main subject of message)
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            the Throwable that describes the cause of the error
	 */
	public static void displayException(Object originator, Component parent, String title,
			String message, Throwable throwable) {
		if (throwable instanceof CryptoException) {
			displayCryptoException(originator, parent, title, message, (CryptoException) throwable);
		}
		else {
			Msg.showError(originator, parent, title, message, throwable);
		}
	}

	private static void displayCryptoException(Object originator, Component parent, String title,
			String message, CryptoException ce) {
		String ce_msg = ce.getMessage();
		if (ce_msg.contains("Install the JCE")) {
			File javaHomeDir = new File(System.getProperty("java.home"));
			File libSecurityDir = new File(new File(javaHomeDir, "lib"), "security");
			//@formatter:off
				if (OptionDialog.showYesNoDialog(parent, title,
					"<html><div style='margin-bottom: 20pt'>A problem with the Java crypto subsystem was encountered:</div>" +
						"<div style='font-weight: bold; margin-bottom: 20pt; margin-left: 50pt'>" + ce_msg + "</div>" +
						"<div style='margin-bottom: 20pt'>Which caused:</div>" +
						"<div style='font-weight: bold; margin-bottom: 20pt; margin-left: 50pt'>" + message + "</div>" +
						"<div style='margin-bottom: 20pt'>This may be fixed by installing the unlimited strength JCE into your JRE's \"lib/security\" directory.</div>" +
						"<div style='margin-bottom: 20pt'>The unlimited strength JCE should be available from the same download location as your JRE.</div>" +
						"<div>Display your JRE's \"lib/security\" directory?</div></html>") == OptionDialog.YES_OPTION) {
				//@formatter:on
				try {
					FileUtilities.openNative(libSecurityDir);
				}
				catch (IOException e) {
					Msg.showError(originator, parent, "Problem starting explorer",
						"Problem starting file explorer: " + e.getMessage());
				}
			}
			return;
		}
		Msg.showWarn(originator, parent, title, message + ": " + ce_msg);
	}

	/**
	 * Copy the contents of a {@link ByteProvider} to a file.
	 * 
	 * @param provider {@link ByteProvider} source of bytes
	 * @param destFile {@link File} destination file
	 * @param monitor {@link TaskMonitor} to update
	 * @return number of bytes copied
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public static long copyByteProviderToFile(ByteProvider provider, File destFile,
			TaskMonitor monitor) throws IOException, CancelledException {
		try (InputStream is = provider.getInputStream(0);
				FileOutputStream fos = new FileOutputStream(destFile)) {
			return streamCopy(is, fos, monitor);
		}
	}

	/**
	 * Copy a stream while updating a TaskMonitor.
	 * 
	 * @param is {@link InputStream} source of bytes 
	 * @param os {@link OutputStream} destination of bytes
	 * @param monitor {@link TaskMonitor} to update
	 * @return number of bytes copied
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public static long streamCopy(InputStream is, OutputStream os, TaskMonitor monitor)
			throws IOException, CancelledException {
		byte buffer[] = new byte[FileUtilities.IO_BUFFER_SIZE];
		int bytesRead;
		long totalBytesCopied = 0;
		while ((bytesRead = is.read(buffer)) > 0) {
			os.write(buffer, 0, bytesRead);
			totalBytesCopied += bytesRead;
			monitor.setProgress(totalBytesCopied);
			monitor.checkCanceled();
		}
		os.flush();
		return totalBytesCopied;
	}

	/**
	 * Returns the text lines in the specified ByteProvider.
	 * <p>
	 * See {@link FileUtilities#getLines(InputStream)}
	 * 
	 * @param byteProvider {@link ByteProvider} to read
	 * @return list of text lines
	 * @throws IOException if error
	 */
	public static List<String> getLines(ByteProvider byteProvider) throws IOException {
		try (InputStream is = byteProvider.getInputStream(0)) {
			return FileUtilities.getLines(is);
		}
	}

	/**
	 * Calculate the MD5 of a file.
	 *
	 * @param f {@link File} to read.
	 * @param monitor {@link TaskMonitor} to watch for cancel
	 * @return md5 as a hex encoded string, never null.
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public static String getFileMD5(File f, TaskMonitor monitor)
			throws IOException, CancelledException {
		try (FileInputStream fis = new FileInputStream(f)) {
			monitor.initialize(f.length());
			monitor.setMessage("Hashing file: " + f.getName());
			return getMD5(fis, monitor);
		}
	}

	/**
	 * Calculate the MD5 of a file.
	 * 
	 * @param provider {@link ByteProvider} 
	 * @param monitor {@link TaskMonitor} to watch for cancel
	 * @return md5 as a hex encoded string, never null.
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public static String getMD5(ByteProvider provider, TaskMonitor monitor)
			throws IOException, CancelledException {
		try (InputStream is = provider.getInputStream(0)) {
			monitor.initialize(provider.length());
			monitor.setMessage("Hashing file: " + provider.getName());
			return getMD5(is, monitor);
		}
	}

	/**
	 * Calculate the hash of an {@link InputStream}.
	 * 
	 * @param is {@link InputStream}
	 * @param monitor {@link TaskMonitor} to update
	 * @return md5 as a hex encoded string, never null
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	public static String getMD5(InputStream is, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(HashUtilities.MD5_ALGORITHM);
			byte[] buf = new byte[16 * 1024];
			int bytesRead;
			while ((bytesRead = is.read(buf)) >= 0) {
				messageDigest.update(buf, 0, bytesRead);
				monitor.incrementProgress(bytesRead);
				monitor.checkCanceled();
			}
			return NumericUtilities.convertBytesToString(messageDigest.digest());
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Concats path strings together, taking care to ensure that there is a correct
	 * path separator character between each part.
	 * <p>
	 * Handles forward or back slashes as path separator characters in the input, but
	 * only adds forward slashes when separating the path strings that need a separator.
	 * <p>
	 * @param paths vararg list of path strings, empty or null elements are ok and are skipped.
	 * @return null if all params null, "" empty string if all are empty, or
	 * "path_element[1]/path_element[2]/.../path_element[N]" otherwise.
	 */
	public static String appendPath(String... paths) {
		if ((CollectionUtils.isAllNull(Arrays.asList(paths)))) {
			return null;
		}

		StringBuilder buffer = new StringBuilder();
		for (String path : paths) {
			if (path == null || path.isEmpty()) {
				continue;
			}

			boolean emptyBuffer = buffer.length() == 0;
			boolean bufferEndsWithSlash =
				!emptyBuffer && "/\\".indexOf(buffer.charAt(buffer.length() - 1)) != -1;
			boolean pathStartsWithSlash = "/\\".indexOf(path.charAt(0)) != -1;

			if (!bufferEndsWithSlash && !pathStartsWithSlash && !emptyBuffer) {
				buffer.append("/");
			}
			else if (pathStartsWithSlash && bufferEndsWithSlash) {
				path = path.substring(1);
			}
			buffer.append(path);
		}

		return buffer.toString();
	}

	/**
	 * Returns the "extension" of the filename part of the path string.
	 * <p>
	 * Ie. everything after the nth last '.' char in the filename, including that '.' character.
	 * <p>
	 * Using: "path/filename.ext1.ext2"
	 * <P>
	 * Gives:
	 * <UL>
	 * 	<LI>extLevel 1: ".ext2"</LI>
	 *  <LI>extLevel 2: ".ext1.ext2"</LI>
	 *  <LI>extLevel 3: <code>null</code></LI>
	 * </UL>
	 *
	 * @param path path/filename.ext string
	 * @param extLevel number of ext levels; must be greater than 0
	 * @return ".ext1" for "path/filename.notext.ext1" level 1, ".ext1.ext2" for
	 *         "path/filename.ext1.ext2" level 2, etc. or null if there was no dot character
	 * @throws IllegalArgumentException if the given level is less than 1
	 */
	public static String getExtension(String path, int extLevel) {

		Objects.requireNonNull(path);
		if (extLevel < 1) {
			throw new IllegalArgumentException("Bad extention level: " + extLevel);
		}

		for (int i = path.length() - 1; i >= 0; i--) {
			char c = path.charAt(i);
			if (SEPARATOR_CHARS.indexOf(c) != -1) { // moved past the filename				
				return null;
			}
			if (c == DOT) {
				if (--extLevel == 0) {
					return path.substring(i);
				}
			}
		}
		return null;
	}

	/**
	 * Returns a copy of the string path that has been fixed to have correct slashes
	 * and a correct leading root slash '/'.
	 *
	 * @param path String forward or backslash path
	 * @return String path with all forward slashes and a leading root slash.
	 */
	public static String normalizeNativePath(String path) {
		return appendPath("/", FilenameUtils.separatorsToUnix(path));
	}

	/**
	 * Common / unified date formatting for all file system information strings.
	 * 
	 * @param d {@link Date} to format, or null
	 * @return formatted date string, or "NA" if date was null
	 */
	public static String formatFSTimestamp(Date d) {
		if (d == null) {
			return "NA";
		}
		SimpleDateFormat df = new SimpleDateFormat("dd MMM yyyy HH:mm:ss z");
		df.setTimeZone(GMT);
		return df.format(d);
	}

	/**
	 * Common / unified size formatting for all file system information strings.
	 * 
	 * @param length {@link Long} length, null ok
	 * @return pretty'ish length format string, or "NA" if length was null
	 */
	public static String formatSize(Long length) {
		return (length != null)
				? String.format("%d (%s)", length, FileUtilities.formatLength(length))
				: "NA";
	}

	/**
	 * Helper method to invoke close() on a Closeable without having to catch
	 * an IOException.
	 * 
	 * @param c {@link Closeable} to close
	 * @param msg optional msg to log if exception is thrown, null is okay
	 */
	public static void uncheckedClose(Closeable c, String msg) {
		try {
			if (c != null) {
				c.close();
			}
		}
		catch (IOException e) {
			Msg.warn(FSUtilities.class, Objects.requireNonNullElse(msg, "Problem closing object"),
				e);
		}
	}
}
