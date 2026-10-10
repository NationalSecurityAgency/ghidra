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
package ghidra.pcode.utils;

import static org.junit.Assert.*;

import java.io.*;
import java.util.zip.DeflaterOutputStream;

import org.junit.Test;

import generic.jar.ResourceFile;

public class SlaFormatTest {

	@Test
	public void testBuildDecoderRejectsOversizedUncompressedSla() throws Exception {
		File slaFile = File.createTempFile("oversized", ".sla");
		slaFile.deleteOnExit();

		try (OutputStream fileStream = new BufferedOutputStream(new FileOutputStream(slaFile))) {
			SlaFormat.writeSlaHeader(fileStream);
			try (DeflaterOutputStream compressedStream = new DeflaterOutputStream(fileStream)) {
				byte[] buffer = new byte[8192];
				int remaining = SlaFormat.MAX_FILE_SIZE + 1;
				while (remaining > 0) {
					int length = Math.min(remaining, buffer.length);
					compressedStream.write(buffer, 0, length);
					remaining -= length;
				}
			}
		}

		IOException exception = assertThrows(IOException.class,
			() -> SlaFormat.buildDecoder(new ResourceFile(slaFile)));
		assertEquals("Uncompressed .sla file exceeds maximum supported size of " +
			SlaFormat.MAX_FILE_SIZE + " bytes", exception.getMessage());
	}
}
