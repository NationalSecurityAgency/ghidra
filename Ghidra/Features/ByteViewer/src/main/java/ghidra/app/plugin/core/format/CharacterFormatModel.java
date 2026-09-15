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
package ghidra.app.plugin.core.format;

import java.awt.FontMetrics;
import java.lang.Character.UnicodeScript;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingActionIf;
import docking.action.builder.ToggleActionBuilder;
import docking.actions.PopupActionProvider;
import ghidra.app.plugin.core.byteviewer.*;
import ghidra.program.model.lang.Endian;
import ghidra.util.*;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.charset.CharsetInfoManager;

/**
 * Converts byte values to Character representation.  (previously the AsciiFormatModel)
 */
public class CharacterFormatModel implements UniversalDataFormatModel, MutableDataFormatModel,
		PopupActionProvider, CursorWidthDataFormatModel, TooltipDataFormatModel {

	public final static String NAME = "Chars";

	private CharsetInfo csi = CharsetInfoManager.getInstance().get(StandardCharsets.US_ASCII);
	private Charset cs = StandardCharsets.US_ASCII;
	private int maxBytesPerChar = 1;
	private boolean compactChars = true;
	private int bytesPerChar = 1;

	public CharacterFormatModel() {
	}

	@Override
	public void setByteViewerConfigOptions(ByteViewerConfigOptions options) {
		this.csi = options.getCharsetInfo();
		this.cs = csi.getCharset();
		this.maxBytesPerChar = Math.max(csi.getMaxBytesPerChar(), 1);
		this.compactChars = options.isCompactChars();
		this.bytesPerChar =
			options.isUseCharAlignment() && csi.getAlignment() > 1 ? csi.getAlignment() : 1;

	}

	@Override
	public int getCursorWidth(FontMetrics fm) {
		return fm.charWidth('W') * (compactChars ? 1 : 2);
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String getDescriptiveName() {
		return NAME + " (%s)".formatted(cs.name());
	}

	@Override
	public int getUnitByteSize() {
		return bytesPerChar;
	}

	@Override
	public int getByteOffset(ByteBlock block, int position) {
		return 0;
	}

	@Override
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	@Override
	public int getDataUnitSymbolSize() {
		return 1;
	}

	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {
		Integer codePoint = getCodePointAt(block, index);
		if (codePoint == null) {
			return "?";
		}
		int cp = codePoint.intValue();
		if (cp == StringUtilities.UNICODE_REPLACEMENT || Character.isISOControl(cp) ||
			!Character.isValidCodePoint(cp)) {
			return ".";
		}
		return Character.toString(cp);
	}

	private Integer getCodePointAt(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {
		// create buffer with as many bytes as it may take to read the largest
		// encoded character using the current charset.
		// This may give us more than 1 character when decoded, we throw away anything
		// other than the first char.

		// Future: would be nice to not have to call getAdjustedCS() for each fetch operation
		Charset bomCS = getAdjustedCS(block);
		byte[] bytes = new byte[maxBytesPerChar];
		int byteCount = block.getBytes(bytes, index, maxBytesPerChar);
		String s = new String(bytes, 0, byteCount, bomCS);
		if (s.isEmpty()) {
			return null;
		}
		return s.codePointAt(0);
	}

	private Charset getAdjustedCS(ByteBlock block) {
		// returns an alternate charset that fits the endianness of the memory
		// to avoid spurious BOM bytes being emitted and incorrect
		// assumption about how to decode bytes
		if (CharsetInfoManager.isBOMCharset(csi.getName())) {
			Endian endian = block.isBigEndian() ? Endian.BIG : Endian.LITTLE;
			CharsetInfo bomCSI =
				CharsetInfoManager.getInstance().get(csi.getName() + endian.toShortString());
			return bomCSI != null ? bomCSI.getCharset() : cs;
		}
		return cs;
	}

	private byte[] getBytesForCodePoint(int cp, Charset bomCS) {
		String s = Character.toString(cp);
		if (bomCS.canEncode() && bomCS.newEncoder().canEncode(s)) {
			ByteBuffer bb = bomCS.encode(s);
			byte[] bytes = new byte[bb.limit()];
			bb.get(bytes);
			return bytes;
		}
		return null;
	}

	@Override
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c)
			throws ByteBlockAccessException {

		if (charPosition != 0) {
			return false;
		}

		block.getByte(index);
		byte cb = (byte) c;

		// right now only supports US-ASCII when replacing values
		if (cb < 0x20 || cb == 0x7f) {
			return false;
		}

		block.setByte(index, cb);
		return true;
	}

	@Override
	public int getUnitDelimiterSize() {
		return 0;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Chars");
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		return List.of(new ToggleActionBuilder("CompactCharWidth", "ByteViewerPlugin")
				.selected(compactChars)
				.withContext(ByteViewerActionContext.class)
				.popupMenuPath("Compact/Wide Layout")
				.onAction(ac -> ac.getComponentProvider().setCompactChars(!compactChars))
				.helpLocation(new HelpLocation("ByteViewerPlugin", "CompactCharWidth"))
				.build());
	}

	@Override
	public String getTooltip(ByteBlock block, BigInteger index, ByteViewerComponent comp) {
		try {
			Integer cp;
			if ((cp = getCodePointAt(block, index)) != null) {
				Charset bomCS = getAdjustedCS(block);
				byte[] bytes = getBytesForCodePoint(cp, bomCS);
				boolean canDisplay = comp.getFont().canDisplay(cp);
				UnicodeScript script = UnicodeScript.of(cp);
				String charRep =
					canDisplay && !Character.isISOControl(cp) ? Character.toString(cp) : "NA";
				String bytesRep = bytes != null
						? NumericUtilities.convertBytesToString(bytes, " ")
						: "unavailable";

				String s = """
						<html>
						<b>Character info:</b><br>
						<table>
						<tr><td>Char</td><td>Unicode</td><td>Script</td></tr>
						<tr><b>%s</b></td><td>0x%04x</td><td>%s</td></tr>
						</table>
						<hr>
						<br>
						%s Bytes: <b>%s</b><br>
						%s
						<br>
						""".formatted(charRep, cp, script, bomCS.name(), bytesRep,
					!canDisplay ? "<br>(unrenderable)" : "");
				return s;
			}
		}
		catch (ByteBlockAccessException e) {
			// ignore
		}
		return null;
	}

}
