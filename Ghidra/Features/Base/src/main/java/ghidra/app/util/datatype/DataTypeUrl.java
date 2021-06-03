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

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;

/**
 * A class to produce and parse URLs of the form:
 * <pre>{@literal
 * 	datatype:/12345678?uid=12345678&name=Bob
 * }</pre>
 * where the first number is the ID of the {@link DataTypeManager} and the second number is 
 * the {@link DataType} ID.
 */
public class DataTypeUrl {

	// see javadoc for format
	private static String PROTOCOL = "datatype";
	private static Pattern URL_PATTERN =
		Pattern.compile(PROTOCOL + ":/(\\d+)\\?uid=(\\d*)&name=(.+)");

	private UniversalID dataTypeManagerId;
	private UniversalID dataTypeId;
	private String dataTypeName;

	/**
	 * Constructs a url from the given data type
	 * @param dt the data type; cannot be null
	 */
	public DataTypeUrl(DataType dt) {
		DataTypeManager dtm = dt.getDataTypeManager();
		dataTypeManagerId = Objects.requireNonNull(dtm.getUniversalID());
		dataTypeId = dt.getUniversalID();
		dataTypeName = Objects.requireNonNull(dt.getName());
	}

	/**
	 * Constructs a url from the given url string
	 * 
	 * @param url the url
	 * @throws IllegalArgumentException if the url does not match the expected {@link #URL_PATTERN}
	 *         or if there is an issue parsing the id within the given url
	 */
	public DataTypeUrl(String url) throws IllegalArgumentException {

		Matcher matcher = URL_PATTERN.matcher(url);
		if (!matcher.matches()) {
			throw new IllegalArgumentException("Invalid data type URL '" + url + "'");
		}

		String dtmId = matcher.group(1);
		String dtId = matcher.group(2);
		dataTypeName = matcher.group(3);

		dataTypeManagerId = new UniversalID(Long.parseLong(dtmId));

		if (!dtId.isBlank()) {
			dataTypeId = new UniversalID(Long.parseLong(dtId));
		}
	}

	public UniversalID getDataTypeManagerId() {
		return dataTypeManagerId;
	}

	public UniversalID getDataTypeId() {
		return dataTypeId;
	}

	public String getDataTypeName() {
		return dataTypeName;
	}

	/**
	 * Uses the given service and its {@link DataTypeManager}s to find the data type 
	 * represented by this url
	 * 
	 * @param service the service
	 * @return the data type; null if there was an error restoring the type, such as if the
	 *         parent {@link DataTypeManager} has been closed
	 */
	public DataType getDataType(DataTypeManagerService service) {

		DataTypeManager manager = findManager(service);
		if (manager == null) {
			return null;
		}

		if (dataTypeId == null) {
			// The ID will be null for built-in types.  In that case, the name will not be
			// null.  Further, built-in types live at the root, so we can just ask for the
			// type by name.
			return manager.getDataType(new DataTypePath(CategoryPath.ROOT, dataTypeName));
		}

		DataType dt = manager.findDataTypeForID(dataTypeId);
		return dt;
	}

	private DataTypeManager findManager(DataTypeManagerService service) {
		return getManagerById(service);
	}

	private DataTypeManager getManagerById(DataTypeManagerService service) {
		DataTypeManager[] mgs = service.getDataTypeManagers();
		for (DataTypeManager dtm : mgs) {
			if (dtm.getUniversalID().equals(dataTypeManagerId)) {
				return dtm;
			}
		}
		return null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((dataTypeId == null) ? 0 : dataTypeId.hashCode());
		result = prime * result + ((dataTypeManagerId == null) ? 0 : dataTypeManagerId.hashCode());
		result = prime * result + ((dataTypeName == null) ? 0 : dataTypeName.hashCode());
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

		DataTypeUrl other = (DataTypeUrl) obj;
		if (!Objects.equals(dataTypeId, other.dataTypeId)) {
			return false;
		}

		if (!Objects.equals(dataTypeManagerId, other.dataTypeManagerId)) {
			return false;
		}

		if (!Objects.equals(dataTypeName, other.dataTypeName)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return PROTOCOL + ":/" + dataTypeManagerId.toString() + "?uid=" +
			Objects.toString(dataTypeId, "") + "&name=" + dataTypeName;
	}
}
