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
package ghidra.file.formats.zstd;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.file.cliwrapper.*;
import ghidra.util.task.TaskMonitor;

/**
 * Wrapper around the zstd cmd line tool
 */
public class ZstdCliToolWrapper extends AbstractCliToolWrapper
		implements StreamDecompressorCliToolWrapper {
	private static final SemVer MIN_VER = SemVer.parse("1.1.0");
	private static final SemVer MAX_VER_EX = SemVer.parse("2.0");

	private static final String NATIVE_EXE_NAME = "zstd";
	private static final Pattern VERSION_STR_PATTERN = Pattern.compile(".*Zstandard.*v([^,]+),.*");

	public static ZstdCliToolWrapper findTool(TaskMonitor monitor) {
		return findToolWrapper(List.of(NATIVE_EXE_NAME), monitor, ZstdCliToolWrapper::new);
	}

	public ZstdCliToolWrapper(File nativeExecutable) {
		super(nativeExecutable);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		try {
			List<String> stdoutLines = new ArrayList<>();
			if (execAndReadStdOut(List.of("--version"), monitor, stdoutLines::add) == 0 &&
				stdoutLines.size() == 1) {
				Matcher m = VERSION_STR_PATTERN.matcher(stdoutLines.get(0));
				if (m.matches()) {
					SemVer ver = SemVer.parse(m.group(1));
					return ver != SemVer.INVALID && MIN_VER.compareTo(ver) <= 0 &&
						MAX_VER_EX.compareTo(ver) > 0;
				}
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return false;
	}

	@Override
	public void decompressStream(InputStream is, OutputStream os, TaskMonitor monitor)
			throws IOException {
		monitor.initialize(0, "Extracting");
		int exitVal;
		// -dcf == decompress, stdout, force
		if ((exitVal = execAndRedirectStdOut(List.of("-dcf"), is, os, monitor)) != 0) {
			throw new IOException("zstd tool error " + exitVal);
		}
	}
}
