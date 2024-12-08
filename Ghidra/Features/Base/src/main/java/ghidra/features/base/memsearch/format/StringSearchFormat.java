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
package ghidra.features.base.memsearch.format;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.*;
import ghidra.util.StringUtilities;

/**
 * {@link SearchFormat} for parsing and display bytes in a string format. This format uses
 * several values from SearchSettings included character encoding, case sensitive, and escape
 * sequences.
 */
class StringSearchFormat extends SearchFormat {
	private final byte CASE_INSENSITIVE_MASK = (byte) 0xdf;

	StringSearchFormat() {
		super("String");
	}

	@Override
	public ByteMatcher parse(String input, SearchSettings settings) {
		input = input.trim();
		if (input.isBlank()) {
			return new InvalidByteMatcher("");
		}

		boolean isBigEndian = settings.isBigEndian();
		int inputLength = input.length();
		Charset charset = settings.getStringCharset();
		if (charset == StandardCharsets.UTF_16) {
			charset = isBigEndian ? StandardCharsets.UTF_16BE : StandardCharsets.UTF_16LE;
		}

		// Escape sequences in the "input" are 2 Characters long.
		if (settings.useEscapeSequences() && inputLength >= 2) {
			input = StringUtilities.convertEscapeSequences(input);
		}
		byte[] bytes = input.getBytes(charset);
		byte[] maskArray = new byte[bytes.length];
		Arrays.fill(maskArray, (byte) 0xff);

		if (!settings.isCaseSensitive()) {
			createCaseInsensitiveBytesAndMasks(charset, bytes, maskArray);
		}

		return new MaskedByteSequenceByteMatcher(input, bytes, maskArray, settings);
	}

	private void createCaseInsensitiveBytesAndMasks(Charset encodingCharSet, byte[] bytes,
			byte[] masks) {
		int i = 0;
		while (i < bytes.length) {
			if (encodingCharSet == StandardCharsets.US_ASCII &&
				Character.isLetter(bytes[i])) {
				masks[i] = CASE_INSENSITIVE_MASK;
				bytes[i] = (byte) (bytes[i] & CASE_INSENSITIVE_MASK);
				i++;
			}
			else if (encodingCharSet == StandardCharsets.UTF_8) {
				int numBytes = bytesPerCharUTF8(bytes[i]);
				if (numBytes == 1 && Character.isLetter(bytes[i])) {
					masks[i] = CASE_INSENSITIVE_MASK;
					bytes[i] = (byte) (bytes[i] & CASE_INSENSITIVE_MASK);
				}
				i += numBytes;
			}
			// Assumes UTF-16 will return 2 Bytes for each character.
			// 4-byte UTF-16 will never satisfy the below checks because
			// none of their bytes can ever be 0.
			else if (encodingCharSet == StandardCharsets.UTF_16BE) {
				if (bytes[i] == (byte) 0x0 && Character.isLetter(bytes[i + 1])) { // Checks if ascii character.
					masks[i + 1] = CASE_INSENSITIVE_MASK;
					bytes[i + 1] = (byte) (bytes[i + 1] & CASE_INSENSITIVE_MASK);
				}
				i += 2;
			}
			else if (encodingCharSet == StandardCharsets.UTF_16LE) {
				if (bytes[i + 1] == (byte) 0x0 && Character.isLetter(bytes[i])) { // Checks if ascii character.
					masks[i] = CASE_INSENSITIVE_MASK;
					bytes[i] = (byte) (bytes[i] & CASE_INSENSITIVE_MASK);
				}
				i += 2;
			}
			else {
				i++;
			}
		}
	}

	private int bytesPerCharUTF8(byte zByte) {
		// This method is intended for UTF-8 encoding.
		// The first byte in a sequence of UTF-8 bytes can tell
		// us how many bytes make up a char.
		int offset = 1;
		// If the char is ascii, this loop will be skipped.
		while ((zByte & 0x80) != 0x00) {
			zByte <<= 1;
			offset++;
		}
		return offset;
	}

	@Override
	public String getToolTip() {
		return "Interpret value as a sequence of characters.";
	}

	@Override
	public String getValueString(byte[] bytes, SearchSettings settings) {
		boolean isBigEndian = settings.isBigEndian();
		Charset charset = settings.getStringCharset();
		if (charset == StandardCharsets.UTF_16) {
			charset = isBigEndian ? StandardCharsets.UTF_16BE : StandardCharsets.UTF_16LE;
		}
		return new String(bytes, charset);
	}

	@Override
	public String convertText(String text, SearchSettings oldSettings, SearchSettings newSettings) {
		return isValidText(text, newSettings) ? text : "";
	}

	@Override
	public SearchFormatType getFormatType() {
		return SearchFormatType.STRING_TYPE;
	}
}
