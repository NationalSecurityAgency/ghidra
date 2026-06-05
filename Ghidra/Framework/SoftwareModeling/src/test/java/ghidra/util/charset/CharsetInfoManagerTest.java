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
package ghidra.util.charset;

import static java.lang.Character.UnicodeScript.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.lang.Character.UnicodeScript;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.util.*;

import org.junit.Ignore;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.charset.CharsetInfoManager.CharsetInfoConfigFile;

public class CharsetInfoManagerTest extends AbstractGenericTest {

	@Test
	public void testCharsetsArePresent() {
		int jvmCharsetCount = Charset.availableCharsets().size();
		int csimCount = CharsetInfoManager.getInstance().getCharsetNames().size();
		assertEquals(jvmCharsetCount, csimCount);
	}

	/**
	 * Generates information about the charsets that are available in the current JVM.  This can
	 * take a couple of minutes, and only needs to be done when there are new charsets of interest.
	 * <p>
	 * Attempts to preserve user-defined comments present in the previous .json file.
	 * <p>
	 * To execute, comment out the Ignore annotation and run as a junit.  Do not leave enabled.
	 * 
	 * @throws IOException if error
	 */
	@Ignore("temporarily enable and run when new charsets need to be categorized")
	@Test
	public void generateCharsetInfoFile() throws IOException {
		File configFilename = CharsetInfoManager.getConfigFileLocation().getFile(false);

		CharsetInfoConfigFile configFile =
			CharsetInfoManager.CharsetInfoConfigFile.read(new ResourceFile(configFilename));
		List<CharsetInfo> existingInfo = new ArrayList<>(configFile.getCharsets());

		Msg.info(this, "Read " + existingInfo.size() + " previous records");

		List<CharsetInfo> newInfo = new ArrayList<>();
		Set<String> standardCharsetNames = Set.copyOf(CharsetInfoManager.getStandardCharsetNames());
		for (String csName : Charset.availableCharsets().keySet()) {
			if (standardCharsetNames.contains(csName) || csName.toLowerCase().contains("utf-")) {
				continue;
			}
			Charset cs = Charset.forName(csName);
			CharsetInfo csi = getCharsetInfoViaEncoder(cs);
			if (csi != null) {
				updateOrAppend(existingInfo, newInfo, csi);
			}
			Msg.info(this, "%s: %s".formatted(csName, csi != null ? "SUCCESS" : "NO INFO"));
		}

		newInfo.sort(CharsetInfoManager.CHARSET_COMP);
		existingInfo.addAll(newInfo);

		String comment = """
				Information about character encodings used by Ghidra.
				Generated on %s by CharsetInfoManagerTest.generateCharsetInfoFile
				""".formatted(new Date());

		CharsetInfoConfigFile newConfigFile = new CharsetInfoConfigFile(comment, existingInfo);
		newConfigFile.write(configFilename);
		Msg.info(this, "Done");
	}

	private void updateOrAppend(List<CharsetInfo> existingList, List<CharsetInfo> newList,
			CharsetInfo newInfo) {
		for (int i = 0; i < existingList.size(); i++) {
			CharsetInfo existing = existingList.get(i);
			if (existing.getName().equals(newInfo.getName())) {
				if (newInfo.getComment() == null && existing.getComment() != null) {
					newInfo = newInfo.withComment(existing.getComment());
				}
				existingList.set(i, newInfo);
				return;
			}
		}
		newList.add(newInfo);
	}

	private CharsetInfo getCharsetInfoViaEncoder(Charset cs) {
		// Creates a CharsetInfo by using the charset's encoder to test what happens for each
		// of the 1.1M unicode codepoints.
		// NOTE: trying to use a charset's decoder to decode every byte sequence into codepoints is
		// not computationally feasible for byte sequences longer than 3.
		EnumSet<UnicodeScript> scripts = EnumSet.noneOf(UnicodeScript.class);
		Set<Integer> byteLens = new HashSet<>();
		int goodCPCount = 0;
		CharsetEncoder encoder = null;
		try {
			encoder = cs.newEncoder();
		}
		catch (UnsupportedOperationException e) {
			return null;
		}

		for (int cp = 1; cp <= Character.MAX_CODE_POINT; cp++) {
			if (cp == StringUtilities.UNICODE_REPLACEMENT || UnicodeScript.of(cp) == UNKNOWN) {
				continue;
			}
			String s = Character.toString(cp);
			if (!encoder.canEncode(s)) {
				continue;
			}
			try {
				CharBuffer cb = CharBuffer.wrap(s);
				ByteBuffer bb = encoder.encode(cb);

				goodCPCount++;
				scripts.add(UnicodeScript.of(cp));
				byte[] bytes = new byte[bb.limit()];
				bb.get(bytes);
				byteLens.add(bytes.length);
			}
			catch (CharacterCodingException e) {
				// skip
			}
		}
		IntSummaryStatistics stats =
			byteLens.stream().mapToInt(Integer::intValue).summaryStatistics();

		// all 255 byte values produce a valid unicode codepoint, with no error mappings possible 
		boolean singleByteFullyMappedCS =
			stats.getMin() == 1 && stats.getMax() == 1 && goodCPCount == 255;

		CharsetInfo csi = new CharsetInfo(cs.name(), null, stats.getMin(), stats.getMax(), 1,
			goodCPCount, false, !singleByteFullyMappedCS, scripts, getCSContains(cs));
		return csi;
	}

	private Set<String> getCSContains(Charset cs) {
		Set<String> result = new HashSet<>();
		for (String csName : Charset.availableCharsets().keySet()) {
			if (!csName.equals(cs.name()) && cs.contains(Charset.forName(csName))) {
				result.add(csName);
			}
		}
		return result;
	}

}
