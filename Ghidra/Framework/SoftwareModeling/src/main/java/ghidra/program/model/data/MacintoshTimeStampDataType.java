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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassTranslator;

/**
 * A datatype to interpret the Mac OS timestamp
 * convention, which is based on the number of 
 * seconds measured from January 1, 1904.
 */
public class MacintoshTimeStampDataType extends BuiltIn {
	static {
		ClassTranslator.put("ghidra.program.model.data.MacintoshTimeStamp",
			MacintoshTimeStampDataType.class.getName());
	}

	private final static SimpleDateFormat formatter = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss");
	private static Date macStartDate;

	static {
		try {
			formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
			macStartDate = formatter.parse("01-Jan-1904 00:00:00");
		}
		catch (Exception e) {
			Msg.error(MacintoshTimeStampDataType.class, "Unexpected Exception: " + e.getMessage(),
				e);
		}
	}

	public MacintoshTimeStampDataType() {
		this(null);
	}

	public MacintoshTimeStampDataType(DataTypeManager dtm) {
		super(null, "MacTime", dtm);
	}

	@Override
	public String getDescription() {
		return "The stamp follows the Macintosh time-measurement scheme "
			+ "(that is, the number of seconds measured from January 1, 1904).";
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "MacTime";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (macStartDate == null) {
			return "unparsed date";
		}
		try {
			long dateInSeconds = buf.getInt(0) & 0xffffffffL;
			long dateInMilliSeconds = dateInSeconds * 1000;
			long start = 0 - macStartDate.getTime();
			Date date = new Date(dateInMilliSeconds - start);
			return formatter.format(date);
		}
		catch (Exception e) {
		}
		return "";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getRepresentation(buf, settings, length);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MacintoshTimeStampDataType(dtm);
	}
}
