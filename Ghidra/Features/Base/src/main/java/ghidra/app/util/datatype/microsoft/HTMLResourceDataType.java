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
package ghidra.app.util.datatype.microsoft;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;

public class HTMLResourceDataType extends BuiltIn implements Dynamic {

	public HTMLResourceDataType() {
		this(null);
	}

	public HTMLResourceDataType(DataTypeManager dtm) {
		super(null, "HTML-Resource", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new HTMLResourceDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "HTML";
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		if (buf != null && maxLength < 0) {
			return maxLength;
		}
		return maxLength;
	}

	@Override
	public String getDescription() {
		return "HTML Resource stored within program";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		byte[] data = new byte[length];
		if (buf.getBytes(data, 0) != length) {
			Msg.error(this, "HTML Resource error: Not enough bytes in memory");
			return null;
		}
		String htmlString = new String(data);
		String rawMessage = HTMLUtilities.fromHTML(htmlString);
		return rawMessage;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return String.class;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (length <= 0) {
			return "??";
		}

		String htmlString = (String) getValue(buf, settings, length);
		if (htmlString == null) {
			return "<HTML-Resource>";
		}

		String rawMessage = HTMLUtilities.fromHTML(htmlString);
		// because JDOM doesn't like 0x00's - don't need them just for rendering the ascii
		rawMessage = rawMessage.replaceAll("\0", "");
		return rawMessage;
	}

	@Override
	public boolean canSpecifyLength() {
		return true;
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}
