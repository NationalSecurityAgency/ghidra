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

import org.junit.Test;

public class IntelHexRecordReaderTest {

	@Test
    public void testBasic() throws Exception {
		IntelHexRecord rawRecord =
			new IntelHexRecord(3, 0x0030, 0, new byte[] { 0x02, 0x33, 0x7a }, 0x1e);
		IntelHexRecord readRecord = IntelHexRecordReader.readRecord(":0300300002337A1E");
		assertEquals(rawRecord, readRecord);
	}
}
