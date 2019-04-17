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
package ghidra.app.util.opinion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.util.exception.AssertException;

public class DefExportLineTest {

	@Test
	public void testExportLineWithOrdinal() {

		//
		// Format: FunctionName @1 PRIVATE
		//
		DefExportLine line = new DefExportLine("BobsHouse @1 PRIVATE");
		assertEquals("BobsHouse", line.getName());
		assertEquals(1, line.getOrdinal());
		assertEquals("PRIVATE", line.getType());
	}

	@Test
	public void testExportLineWithoutOrdinal() {

		//
		// Format: FunctionName PRIVATE
		//
		DefExportLine line = new DefExportLine("BobsHouse PRIVATE");
		assertEquals("BobsHouse", line.getName());
		assertEquals(0, line.getOrdinal());
		assertEquals("PRIVATE", line.getType());
	}

	@Test
	public void testExportLineWithoutPrivateKeyword() {

		//
		// Format: FunctionName PRIVATE
		//
		DefExportLine line = new DefExportLine("BobsHouse @1");
		assertEquals("BobsHouse", line.getName());
		assertEquals(1, line.getOrdinal());
		assertEquals(null, line.getType());
	}

	@Test
	public void testExportLineWithoutOrdinalOrPrivateKeyword() {

		//
		// Format: FunctionName PRIVATE
		//
		DefExportLine line = new DefExportLine("BobsHouse");
		assertEquals("BobsHouse", line.getName());
		assertEquals(0, line.getOrdinal());
		assertEquals(null, line.getType());
	}

	@Test
	public void testExportLineWithInvalidFormat() {
		try {
			new DefExportLine("one two three four");
			fail("Did not get a parsing exception with an invalid format");
		}
		catch (AssertException e) {
			// expected
		}
	}
}
