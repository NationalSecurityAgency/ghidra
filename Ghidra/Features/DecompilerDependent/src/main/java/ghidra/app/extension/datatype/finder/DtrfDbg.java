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
package ghidra.app.extension.datatype.finder;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.lang3.StringUtils;

import generic.io.NullPrintWriter;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;

/**
 * A package utility class to allow for tests to selectively enable debug output.  This class is
 * used instead of generic logging with the intent that this class will be removed when the bug(s)
 * are fixed.
 */
class DtrfDbg {

	private static ByteArrayOutputStream debugBytes;
	private static PrintWriter debugWriter = new NullPrintWriter();

	private static List<String> clientFilters = new ArrayList<>();

	private static Map<Function, List<String>> linesByFunction = new ConcurrentHashMap<>();

	DtrfDbg() {
		// static class
	}

	static void enable() {
		debugBytes = new ByteArrayOutputStream();
		debugWriter = new PrintWriter(debugBytes);
	}

	private static void close() {
		debugWriter.close();
		debugWriter = new NullPrintWriter();
	}

	static void disable(boolean write) {

		if (!write) {
			close();
			return;
		}

		Set<Entry<Function, List<String>>> entries = linesByFunction.entrySet();
		for (Entry<Function, List<String>> entry : entries) {
			Function function = entry.getKey();
			List<String> lines = entry.getValue();
			debugWriter.println("\n\nFunction Debug: " + function.getName());
			for (String line : lines) {
				debugWriter.println(line);
			}
		}

		debugWriter.flush();
		String output = debugBytes.toString();
		if (!StringUtils.isBlank(output)) {
			Msg.debug(DtrfDbg.class, "\n\nFinal Debug:\n" + output);
		}

		close();
	}

	/**
	 * Sets filters that will be checked against the {@code toString()} of each client.  The
	 * filtering is a case-sensitive 'contains' check.
	 * @param filters the text
	 */
	static void setClientToStringFilters(String... filters) {
		clientFilters.clear();
		clientFilters.addAll(Arrays.asList(filters));
	}

	static void println(Function f, String s) {
		linesByFunction.computeIfAbsent(f, ff -> new ArrayList<>()).add(s);
	}

	static void println(Function f, Object client, String s) {
		if (!passesFilter(client)) {
			return;
		}

		linesByFunction.computeIfAbsent(f, ff -> new ArrayList<>()).add(s);
	}

	private static boolean passesFilter(Object client) {
		if (client == null || clientFilters.isEmpty()) {
			return true;
		}

		String asString = client.toString();
		return clientFilters.stream().anyMatch(s -> asString.contains(s));
	}
}
