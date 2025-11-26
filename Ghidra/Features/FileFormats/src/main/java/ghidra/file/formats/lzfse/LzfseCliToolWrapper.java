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
package ghidra.file.formats.lzfse;

import java.io.*;
import java.util.List;

import ghidra.file.cliwrapper.AbstractCliToolWrapper;
import ghidra.file.cliwrapper.StreamDecompressorCliToolWrapper;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Wrapper around the lzfse cmd line tool.  This tool is typically provided in the Ghidra distro
 * (see {@link Application#getOSFile(String)}.
 */
public class LzfseCliToolWrapper extends AbstractCliToolWrapper
		implements StreamDecompressorCliToolWrapper {
	private static final String LZFSE_NATIVE_BINARY_NAME = "lzfse";

	/**
	 * Creates a new tool wrapper around the OS specific lzfse cmd line tool found in Ghidra's
	 * distro.
	 *  
	 * @param monitor {@link TaskMonitor}
	 * @return new {@link LzfseCliToolWrapper} instance, or {@code null} if not found
	 */
	public static LzfseCliToolWrapper findTool(TaskMonitor monitor) {
		try {
			String lzfseName = LZFSE_NATIVE_BINARY_NAME;
			if (OperatingSystem.CURRENT_OPERATING_SYSTEM.equals(OperatingSystem.WINDOWS)) {
				lzfseName += ".exe";
			}
			File lzfseNativeBinary = Application.getOSFile(lzfseName);
			if (lzfseNativeBinary != null) {
				LzfseCliToolWrapper tmpTool = new LzfseCliToolWrapper(lzfseNativeBinary);
				if (tmpTool.isValid(monitor)) {
					return tmpTool;
				}
			}
		}
		catch (IOException e) {
			// fall thru, return null
		}
		return null;
	}

	public LzfseCliToolWrapper(File nativeExecutable) {
		super(nativeExecutable);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		try {
			// if it executes with good exit value, consider it valid
			StringBuilder sb = new StringBuilder();
			if (execAndReadStdOut(List.of("-h"), monitor, sb::append) == 0) {
				return true;
			}
		}
		catch (IOException e) {
			// fall thru
		}
		return false;
	}

	@Override
	public void decompressStream(InputStream is, OutputStream os, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.initialize(0, "Extracting");
		int exitVal = execAndRedirectStdOut(List.of("-decode"), is, os, monitor);
		if (exitVal != 0) {
			throw new IOException("lzfse tool error " + exitVal);
		}
	}

}
