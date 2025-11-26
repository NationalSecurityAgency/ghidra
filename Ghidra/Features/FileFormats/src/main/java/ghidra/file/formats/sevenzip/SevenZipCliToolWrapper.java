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
package ghidra.file.formats.sevenzip;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.file.cliwrapper.*;
import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.framework.OperatingSystem;
import ghidra.util.task.TaskMonitor;

/**
 * Wrapper around 7z cli tool
 */
public class SevenZipCliToolWrapper extends AbstractCliToolWrapper
		implements ArchiverCliToolWrapper {
	private static final SemVer MIN_SUPPORTED_VER = SemVer.parse("23.0");
	private static final List<String> NATIVE_UNIX_EXE_NAMES = List.of("7zz", "7zzs", "7z");
	private static final List<String> NATIVE_WIN_EXE_NAMES = List.of("7z.exe");
	private static final Pattern SZ_VER_PATTERN =
		Pattern.compile(".*7-Zip \\(z\\) ([0-9.]+) .*Copyright \\(c\\).*");

	private static final List<String> getCurrentOSNativeExeNames() {
		return switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case OperatingSystem.WINDOWS -> NATIVE_WIN_EXE_NAMES;
			default -> NATIVE_UNIX_EXE_NAMES;
		};
	}

	public static SevenZipCliToolWrapper findTool(TaskMonitor monitor) {
		return findToolWrapper(getCurrentOSNativeExeNames(), monitor, SevenZipCliToolWrapper::new);
	}

	public SevenZipCliToolWrapper(File nativeExecutable) {
		super(nativeExecutable);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		try {
			StringBuilder sb = new StringBuilder();
			if (execAndReadStdOut(List.of("--help"), monitor, sb::append) == 0) {
				Matcher m = SZ_VER_PATTERN.matcher(sb.toString());
				if (m.matches()) {
					SemVer ver = SemVer.parse(m.group(1));
					return ver != SemVer.INVALID && ver.compareTo(MIN_SUPPORTED_VER) >= 0;
				}
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return false;
	}

	@Override
	public void extract(File archiveFile, Entry entry, OutputStream os, TaskMonitor monitor)
			throws IOException {
		// -so = pipe extract output to stdout
		// e = extract
		int exitVal = execAndRedirectStdOut(
			List.of("-so", "e", archiveFile.getPath(), entry.name()), null, os, monitor);
		if (exitVal != 0) {
			throw new IOException(
				"Error during extraction: %s, retVal: %d".formatted(nativeExecutable, exitVal));
		}
	}

	@Override
	public List<Entry> getListing(File archiveFile, TaskMonitor monitor) {
		try {
			List<String> lines = new ArrayList<>();
			if (execAndReadStdOut(List.of("l", archiveFile.getPath()), monitor, lines::add) != 0) {
				return List.of();
			}
			boolean inListingSection = false;
			List<Entry> results = new ArrayList<>();
			for (int lineNum = 0; lineNum < lines.size(); lineNum++) {
				String line = lines.get(lineNum);
				if (isListingStartEndLine(line)) {
					if (inListingSection) {
						break;
					}
					inListingSection = true;
				}
				else if (inListingSection && line.length() >= NAME_START) {
					SevenZipListingLine ll = parseListingLine(line);
					results.add(new Entry(ll.name, ll.size, ll.fileType));
				}
			}
			return results;
		}
		catch (IOException e) {
			// fall thru
		}
		return List.of();

	}

	private static final int DATETIME_START = 0;
	private static final int DATETIME_LEN = 10 + 1 + 8;
	private static final int ATTR_START = DATETIME_START + DATETIME_LEN + 1;
	private static final int ATTR_LEN = 5;
	private static final int SIZE_START = ATTR_START + ATTR_LEN + 1;
	private static final int SIZE_LEN = 12;
	private static final int COMPRESSED_START = SIZE_START + SIZE_LEN + 1;
	private static final int COMPRESSED_LEN = 12;
	private static final int NAME_START = COMPRESSED_START + COMPRESSED_LEN + 1 + 1 /* 2 spaces */;

	private SimpleDateFormat listingDateTimeFormat = new SimpleDateFormat("yyy-MM-dd HH:mm:ss");

	private SevenZipListingLine parseListingLine(String s) {
		String datetimeStr = s.substring(DATETIME_START, DATETIME_START + DATETIME_LEN);
		String attrStr = s.substring(ATTR_START, ATTR_START + ATTR_LEN);
		String sizeStr = s.substring(SIZE_START, SIZE_START + SIZE_LEN);
		String compressedStr = s.substring(COMPRESSED_START, COMPRESSED_START + COMPRESSED_LEN);
		String name = s.substring(NAME_START);

		long dateMS = parseDateElse(listingDateTimeFormat, datetimeStr, 0);
		FileType fileType = parseAttrs(attrStr);
		long size = parseSize(sizeStr);
		long compressedSize = parseSize(compressedStr);

		return new SevenZipListingLine(dateMS, fileType, size, compressedSize, name);
	}

	private FileType parseAttrs(String s) {
		return s.length() == 5 && s.charAt(0) == 'D' ? FileType.DIRECTORY : FileType.FILE;
	}

	private static long parseSize(String s) {
		try {
			return Long.parseLong(s.trim());
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	private static long parseDateElse(SimpleDateFormat sdf, String s, long defaultValue) {
		try {
			return sdf.parse(s).getTime();
		}
		catch (ParseException e) {
			return defaultValue;
		}
	}

	record SevenZipListingLine(long date, FileType fileType, long size, long compressedSize,
			String name) {

	}

	private boolean isListingStartEndLine(String s) {
		String[] parts = s.split(" +");
		return parts.length == 5 && isAll(parts[0], "-") && isAll(parts[1], "-") &&
			isAll(parts[2], "-") && isAll(parts[3], "-") && isAll(parts[4], "-");
	}

	private boolean isAll(String s, String ch) {
		return !s.isEmpty() && ch.repeat(s.length()).equals(s);
	}

}
