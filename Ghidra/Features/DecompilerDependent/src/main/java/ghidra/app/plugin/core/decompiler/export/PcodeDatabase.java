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
import java.util.*;
import java.util.concurrent.*;

import ghidra.util.Msg;

public class PcodeDatabase {
	private static final char DBSEP = '\t';
	private static final char EOL = '\n';

	protected Map<String, Collection<List<String>>> contents = new ConcurrentHashMap<>();

	public void writeFile(Collection<List<String>> contentList, String predicateFile,
			String directory) throws IOException {
		File factsFile = new File(directory, predicateFile + ".facts");
		Writer w = new BufferedWriter(new FileWriter(factsFile, true));
		for (List<String> record : contentList) {
			writeRecord(w, record);
		}
		w.flush();
		w.close();
	}

	public synchronized void writeFacts(String directory, boolean writeAll) {
		final int k = Runtime.getRuntime().availableProcessors() * 2 - 1;
		ExecutorService es = Executors.newFixedThreadPool(k);
		for (String fn : contents.keySet()) {
			es.execute(() -> {
				try {
					writeFile(contents.get(fn), fn, directory);
				}
				catch (Exception e) {
					// System.out.println(e);
					ghidra.util.Msg.info(this, e);
					for (StackTraceElement st : e.getStackTrace()) {
						ghidra.util.Msg.info(this, st);
					}
				}
			});
		}

		es.shutdown();
		try {
			while (!es.awaitTermination(30, TimeUnit.SECONDS))
				;
		}
		catch (Exception e) {
			// System.out.println(e);
			Msg.info(this, e);
			for (StackTraceElement st : e.getStackTrace()) {
				ghidra.util.Msg.info(this, st);
			}
		}

		this.clear(writeAll);
	}

	private void writeRecord(Writer writer, List<String> record) throws IOException {
		boolean first = true;
		for (String col : record) {
			if (col == null) {
				col = "UNKNOWN";
			}
			if (!first) {
				writer.write(DBSEP);
			}
			writeColumn(writer, col);
			first = false;
		}
		writer.write(EOL);
	}

	private void writeColumn(Writer writer, String column) throws IOException {
		// Quote some special characters.
		for (int i = 0; i < column.length(); i++) {
			char c = column.charAt(i);
			switch (c) {
				case '\"' -> writer.write("'");
				case '\\' -> {
					writer.write('\\');
					writer.write('\\');
				}
				case EOL -> {
					writer.write('\\');
					writer.write('n');
				}
				case '\t' -> {
					writer.write('\\');
					writer.write('t');
				}
				default -> writer.write(c);
			}
		}
	}

	public synchronized void addExport(String filename, String... args) {
		this.contents.computeIfAbsent(filename, _ -> new HashSet<>())
				.add(Arrays.asList(args));
	}

	public void clear(boolean clearAll) {
		contents = new ConcurrentHashMap<>();
	}
}
