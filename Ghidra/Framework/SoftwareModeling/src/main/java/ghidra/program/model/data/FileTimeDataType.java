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
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassTranslator;

/**
 * A datatype to interpret the FILETIME timestamp
 * convention, which is based on the number of 100-nanosecond ticks
 * since January 1, 1601.
 */
public class FileTimeDataType extends BuiltIn {
	static {
		ClassTranslator.put("ghidra.program.model.data.FileTime", FileTimeDataType.class.getName());
	}

	private final static SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private static Date epochData;

	static {
		try {
			formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
			epochData = formatter.parse("1601-01-01 00:00:00");
		}
		catch (Exception e) {
			Msg.error(FileTimeDataType.class, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	public FileTimeDataType() {
		this(null);
	}

	public FileTimeDataType(DataTypeManager dtm) {
		super(null, "FileTime", dtm);
	}

	@Override
	public String getDescription() {
		return "The stamp follows the Filetime-measurement scheme " +
			"(that is, the number of 100 nanosecond ticks measured from midnight January 1, 1601).";
	}

	@Override
	public int getLength() {
		return 8;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "FileTime";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (epochData == null) {
			return "unparsed date";
		}

		try {
			long numTicks = buf.getLong(0);
			long numMilliSeconds = numTicks / 10000;
			long start = 0 - epochData.getTime();
			Date date = new Date(numMilliSeconds - start);
			long fractionalPartPlus1e8 = numTicks % 10000000 + 100000000;
			String fractionalPart = Long.toString(fractionalPartPlus1e8).substring(1);
			return formatter.format(date) + "." + fractionalPart + " UTC";
		}
		catch (Exception e) {
			// format parse failed or no memory
		}
		return "";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			long numTicks = buf.getLong(0);
			return new Long(numTicks);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Long.class;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new FileTimeDataType(dtm);
	}

}
