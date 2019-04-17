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

import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.Test;

public class IntelHexRecordTest {

	@Test
    public void testCtor() throws Exception {
		try {
			new IntelHexRecord(0, 0, -1, new byte[0], 0);
			Assert.fail("bad record type -1");
		}
		catch (IllegalArgumentException iae) {
			// valid
		}
		catch (Exception e) {
			Assert.fail("huh? " + e.getMessage());
		}
		try {
			new IntelHexRecord(0, 0, 6, new byte[0], 0);
			Assert.fail("bad record type 6");
		}
		catch (IllegalArgumentException iae) {
			// valid
		}
		catch (Exception e) {
			Assert.fail("huh? " + e.getMessage());
		}
		try {
			new IntelHexRecord(15, 0, 0, new byte[0], 0);
			Assert.fail("recordLength != data.length");
		}
		catch (IllegalArgumentException iae) {
			// valid
		}
		catch (Exception e) {
			Assert.fail("huh? " + e.getMessage());
		}
		// should pass
		new IntelHexRecord(0, 0, 1, new byte[0], 0xff);
		new IntelHexRecord(3, 0x0030, 0, new byte[] { 0x02, 0x33, 0x7a }, 0x1e);
	}

	@Test
    public void testChecksum() throws Exception {
		IntelHexRecord record = new IntelHexRecord(1, 0, 0, new byte[] { 4 }, 37);
		assertTrue("incorrect", !record.isReportedChecksumCorrect());
		record = new IntelHexRecord(3, 0x0030, 0, new byte[] { 0x02, 0x33, 0x7a }, 0x1e);
		assertTrue("correct", record.isReportedChecksumCorrect());
	}
}
