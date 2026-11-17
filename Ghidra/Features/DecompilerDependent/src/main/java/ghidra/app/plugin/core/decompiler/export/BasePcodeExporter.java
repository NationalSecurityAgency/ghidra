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
package ghidra.app.plugin.core.decompiler.export;

import java.io.*;

public class BasePcodeExporter {

	protected final PcodeDatabase db = new PcodeDatabase();
	protected final Writer debug;
	protected final String directory;

	final static char SEP = ':';
	final static char TAB = '\t';
	final static char QUOTE = '\"';

	public BasePcodeExporter(String directory) throws IOException {
		this.directory = directory;
		deleteStaleFactsDirectory(directory);
		debug = new BufferedWriter(new FileWriter(new File(directory, "PcodeOps.facts")));
	}

	/**
	 * Facts files are opened in append mode so that incremental flushes within a single
	 * export accumulate.  Without cleaning the output directory first, a re-export into
	 * the same directory would append to (and corrupt) the facts from the previous run.
	 * @param dirName where the facts go
	 */
	private void deleteStaleFactsDirectory(String dirName) {
		File dir = new File(dirName);
		File[] stale = dir.listFiles((_, nm) -> nm.endsWith(".facts"));
		if (stale == null) {
			return;
		}
		for (File f : stale) {
			f.delete();
		}
	}

	public void writeFacts(boolean writeAll) {
		db.writeFacts(directory, writeAll);
	}

	public void writeDebug() throws IOException {
		debug.close();
	}

	public PcodeDatabase getDatabase() {
		return db;
	}

	void export(String pfile, String key, String value) {
		db.addExport(pfile, key, value);
	}


	protected void debug(String s) {
		try {
			this.debug.write(s);
			this.debug.write('\n');
		}
		catch (IOException e) {
			throw new RuntimeException(e.toString());
		}
		db.addExport("PcodeOps", s);
	}
}
