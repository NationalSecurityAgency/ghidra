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
package ghidra.app.util.exporter;

import java.io.*;
import java.util.List;

import org.junit.Assert;

import ghidra.util.Msg;

public class StringComparer {
	public static void compareLines(List<String> expectedList, File actualFile) throws Exception {
		int index = 0;

		boolean hasFailure = false;

		try (BufferedReader reader = new BufferedReader(new FileReader(actualFile))) {
			int excess = 0;
			while (true) {
				String actualLine = reader.readLine();
				if (actualLine == null) {
					break;
				}

				if (index >= expectedList.size()) {
					++excess;
					continue;
				}
				String expectedLine = expectedList.get(index++);

				actualLine = actualLine.trim();
				expectedLine = expectedLine.trim();

				boolean match =
					expectedLine.equals(actualLine) || actualLine.startsWith(expectedLine);

				hasFailure |= !match;

				if (!match) {
					Msg.debug(StringComparer.class, "Expected line does not match actual line (" + index +
						"): \nExpected: " + expectedLine + "\nActual: " + actualLine);
				}
			}

			if (excess > 0) {
				String message = "Actual file contains " + excess + " more lines than expected";
				Msg.debug(StringComparer.class, message);
				Assert.fail(message);
			}
			else if (!hasFailure && index < expectedList.size()) {
				int fewer = expectedList.size() - index;
				String message = "Actual file contains " + fewer +
					" fewer lines than expected";
				Msg.debug(StringComparer.class, message);
				Assert.fail(message);
			}

			if (hasFailure) {
				Assert.fail("One or more failures--see output for data");
			}
		}
	}
}
