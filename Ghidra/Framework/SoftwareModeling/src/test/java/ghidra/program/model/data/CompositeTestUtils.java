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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.util.*;

import ghidra.util.Msg;

public class CompositeTestUtils {

	private CompositeTestUtils() {
		// no construct
	}

	/**
	 * Compare dump of composite with the expected on
	 * @param test JUnit test instance used for reporting
	 * @param expectedDump expected composite dump
	 * @param composite test result composite
	 */
	public static void assertExpectedComposite(Object test, String expectedDump,
			DataType composite) {
		assertExpectedComposite(test, expectedDump, composite, false);
	}

	/**
	 * Compare dump of composite with the expected on
	 * @param test JUnit test instance used for reporting
	 * @param expectedDump expected composite dump
	 * @param composite test result composite
	 * @param recursive if true all child composites will be included in dump
	 */
	public static void assertExpectedComposite(Object test, String expectedDump, DataType composite,
			boolean recursive) {
		assertTrue(composite instanceof Composite);
		String result = dump(composite, recursive).trim();
		expectedDump = expectedDump.trim();
		int len = expectedDump.length();
		int expectedLine = 1;
		int expectedCol = 0;
		int index = 0;
		boolean mismatch = false;

		for (index = 0; index < len; index++) {
			++expectedCol;
			char expectedChar = expectedDump.charAt(index);
			if (expectedChar == '\n') {
				++expectedLine;
				expectedCol = 0; // newline
			}
			char resultChar = (index < result.length()) ? result.charAt(index) : 0;
			if (resultChar != expectedChar) {
				Msg.error(test, "Expected and result differ: expected line " + expectedLine +
					", column " + expectedCol);
				mismatch = true;
				break;
			}
		}

		mismatch |= len != result.length();

		if (mismatch) {
			Msg.error(test, "Expected composite:\n" + expectedDump);
			Msg.error(test, "Result composite:\n" + result);
			fail("Failed to parse expected composite (see log)");
		}
	}

	private static Comparator<Composite> NAME_COMPARATOR =
		(o1, o2) -> o1.getPathName().compareTo(o2.getPathName());

	/**
	 * Dump composite details for examination or test comparison.
	 * @param dt composite datatype
	 * @param recursive if true all child composites will also be dumped recursively
	 * @return dump string
	 */
	public static String dump(DataType dt, boolean recursive) {
		if (!(dt instanceof Composite)) {
			return "";
		}

		Composite composite = (Composite) dt;
		StringBuilder buf = new StringBuilder();
		buf.append(composite.toString());

		if (recursive) {
			TreeSet<Composite> otherComposites = new TreeSet<>(NAME_COMPARATOR);
			collectComposites(composite, otherComposites);
			for (Composite child : otherComposites) {
				buf.append(child.toString());
			}
		}
		return buf.toString();
	}

	private static void collectComposites(Composite composite, Set<Composite> collection) {
		for (DataTypeComponent c : composite.getDefinedComponents()) {
			DataType dt = c.getDataType();
			if (dt instanceof Composite) {
				Composite childComposite = (Composite) dt;
				collection.add(childComposite);
				collectComposites(childComposite, collection);
			}
		}
	}
}
