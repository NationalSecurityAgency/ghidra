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
package ghidra.app.plugin.core.strings;

import java.io.IOException;
import java.util.*;

/**
 * Three (3) adjacent characters, with \0 being reserved for start and end of string magic values.
 * 
 * @param codePoints 3 characters (as int32 code points)
 */
public record Trigram(int[] codePoints) implements Comparable<Trigram> {

	public static Trigram of(int cp1, int cp2, int cp3) {
		return new Trigram(new int[] { cp1, cp2, cp3 });
	}

	public static Trigram fromStringRep(String s1, String s2, String s3)
			throws NumberFormatException, IOException {
		return Trigram.of(decodeCodePoint(s1), decodeCodePoint(s2), decodeCodePoint(s3));
	}

	public static StringTrigramIterator iterate(String s) {
		return new StringTrigramIterator(s);
	}

	public String toCharSeq() {
		return getCodePointRepresentation(codePoints[0]) +
			getCodePointRepresentation(codePoints[1]) +
			getCodePointRepresentation(codePoints[2]);
	}

	@Override
	public String toString() {
		return toCharSeq();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(codePoints);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Trigram other = (Trigram) obj;
		return Arrays.equals(codePoints, other.codePoints);
	}

	@Override
	public int compareTo(Trigram o) {
		int result = Integer.compare(codePoints[0], o.codePoints[0]);
		result = result == 0 ? Integer.compare(codePoints[1], o.codePoints[1]) : result;
		result = result == 0 ? Integer.compare(codePoints[2], o.codePoints[2]) : result;
		return result;
	}
	//--------------------------------------------------------------------------------------------
	private static final String START_OF_STRING = "[^]";

	private static final String END_OF_STRING = "[$]";
	private static final Set<String> META_CHARS = Set.of(START_OF_STRING, END_OF_STRING);
	private static final Map<String, Integer> descriptionToCodePoint = new HashMap<>();
	private static final Map<Integer, String> codePointToDescription = new HashMap<>();

	private static void mapCP(String desc, int codePoint) {
		descriptionToCodePoint.put(desc, codePoint);
		codePointToDescription.put(codePoint, desc);
	}
	static {
		mapCP("[NUL]", 0);
		mapCP("[SOH]", 1);
		mapCP("[STX]", 2);
		mapCP("[ETX]", 3);
		mapCP("[EOT]", 4);
		mapCP("[ENQ]", 5);
		mapCP("[ACK]", 6);
		mapCP("[BEL]", 7);
		mapCP("[BS]", 8);
		mapCP("[HT]", 9);
		mapCP("[LF]", 10);
		mapCP("[VT]", 11);
		mapCP("[FF]", 12);
		mapCP("[CR]", 13);
		mapCP("[SO]", 14);
		mapCP("[SI]", 15);
		mapCP("[DLE]", 16);
		mapCP("[DC1]", 17);
		mapCP("[DC2]", 18);
		mapCP("[DC3]", 19);
		mapCP("[DC4]", 20);
		mapCP("[NAK]", 21);
		mapCP("[SYN]", 22);
		mapCP("[ETB]", 23);
		mapCP("[CAN]", 24);
		mapCP("[EM]", 25);
		mapCP("[SUB]", 26);
		mapCP("[ESC]", 27);
		mapCP("[FS]", 28);
		mapCP("[GS]", 29);
		mapCP("[RS]", 30);
		mapCP("[US]", 31);
		mapCP("[SP]", 32);
		mapCP("[DEL]", 127);
	}

	static String getCodePointRepresentation(int codePoint) {
		if (codePoint >= 33 && codePoint <= 126) {
			return Character.toString(codePoint);
		}
		String result = codePointToDescription.get(codePoint);
		if (result != null) {
			return result;
		}
		return codePoint > 0 && codePoint <= 0xFFFF
				? "\\u%04X".formatted(codePoint)
				: "\\U%08X".formatted(codePoint);
	}

	private static int decodeCodePoint(String rep) throws IOException, NumberFormatException {
		if (rep == null || rep.isEmpty()) {
			throw new IOException("Invalid character symbol in model file");
		}
		if (rep.codePointCount(0, rep.length()) == 1) {
			return rep.codePointAt(0);
		}
		if (rep.length() == 3 && META_CHARS.contains(rep)) {
			// convert $, ^ (start-of-line, end-of-line) to null char
			return '\0';
		}
		if (rep.length() == 6 && rep.startsWith("\\u")) {
			// "\uFFFF"
			return Integer.parseUnsignedInt(rep, 2, 6, 16);
		}
		if (rep.length() == 10 && rep.startsWith("\\U")) {
			// "\uFFFFFFFF"
			return Integer.parseUnsignedInt(rep, 2, 10, 16);
		}
		if (rep.startsWith("[")) {
			// one of the "[xx]" codes
			Integer codePoint = descriptionToCodePoint.get(rep);
			if (codePoint == null) {
				throw new IOException("Can not parse character " + rep + " in model file");
			}
			return codePoint;
		}
		return rep.codePointAt(0);
	}

}
