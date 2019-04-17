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
package ghidra.app.util.datatype;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import ghidra.util.UniversalID;

/**
 * A class to produce and parse URLs of the form:
 * <pre>
 * 	datatype:/12345678/12345678
 * </pre>
 * where the first number is the ID of the {@link DataTypeManager} and the second number is 
 * the {@link DataType} ID.
 */
public class DataTypeIdUrl {

	private static String PROTOCOL = "datatype";
	private static Pattern URL_PATTERN = Pattern.compile(PROTOCOL + ":/(\\d+)/(\\d+)");

	private UniversalID dataTypeManagerId;
	private UniversalID dataTypeId;

	public DataTypeIdUrl(DataType dt) {
		DataTypeManager dtm = dt.getDataTypeManager();
		if (dtm == null) {
			Msg.debug(this, "");
		}
		dataTypeManagerId = dtm.getUniversalID();
		dataTypeId = dt.getUniversalID();
	}

	public DataTypeIdUrl(String url) {

		Matcher matcher = URL_PATTERN.matcher(url);
		if (!matcher.matches()) {
			throw new IllegalArgumentException("Invalid data type URL '" + url + "'");
		}

		String dtmId = matcher.group(1);
		String dtId = matcher.group(2);
		dataTypeManagerId = new UniversalID(Long.parseLong(dtmId));
		dataTypeId = new UniversalID(Long.parseLong(dtId));
	}

	public UniversalID getDataTypeManagerId() {
		return dataTypeManagerId;
	}

	public UniversalID getDataTypeId() {
		return dataTypeId;
	}

	@Override
	public String toString() {
		return PROTOCOL + ":/" + dataTypeManagerId.toString() + '/' + dataTypeId.toString();
	}
}
