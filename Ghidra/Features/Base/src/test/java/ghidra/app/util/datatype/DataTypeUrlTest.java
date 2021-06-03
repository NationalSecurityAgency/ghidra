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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.TestDoubleDataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;

public class DataTypeUrlTest {

	@Before
	public void setUp() {
		UniversalIdGenerator.initialize();
	}

	@Test
	public void testConstructor_FromDataType() throws Exception {

		String name = "string";
		FakeDataType dt = new FakeDataType(name);
		DataTypeUrl dtUrl = new DataTypeUrl(dt);

		assertNotNull(dtUrl.getDataTypeManagerId());
		assertNotNull(dtUrl.getDataTypeId());
		assertEquals(name, dtUrl.getDataTypeName());
	}

	@Test
	public void testConstructor_FromUrlString_AllDataIncluded() throws Exception {

		String dtmId = "3295333330922457057";
		String dtId = "3295333330922457056";
		String name = "string";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		DataTypeUrl dtUrl = new DataTypeUrl(urlString);
		assertNotNull(dtUrl.getDataTypeManagerId());
		assertNotNull(dtUrl.getDataTypeId());
		assertEquals(name, dtUrl.getDataTypeName());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructor_FromUrlString_AllDataIncluded_BadDataTypeManagerId()
			throws Exception {

		String dtmId = "123bad_id123";
		String dtId = "3295333330922457056";
		String name = "string";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		new DataTypeUrl(urlString);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructor_FromUrlString_AllDataIncluded_BadDataTypeId() throws Exception {

		String dtmId = "3295333330922457057";
		String dtId = "bad_id";
		String name = "string";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		new DataTypeUrl(urlString);
	}

	@Test
	public void testConstructor_FromUrlString_NoDataTypeId() throws Exception {

		String dtmId = "3295333330922457057";
		String dtId = "";
		String name = "string";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		DataTypeUrl dtUrl = new DataTypeUrl(urlString);
		assertNotNull(dtUrl.getDataTypeManagerId());
		assertNull(dtUrl.getDataTypeId());
		assertEquals(name, dtUrl.getDataTypeName());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructor_FromUrlString_NoDataTypeManagerId() throws Exception {

		String dtmId = "";
		String dtId = "3295333330922457056";
		String name = "string";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		new DataTypeUrl(urlString);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructor_FromUrlString_NoDataTypeName() throws Exception {

		String dtmId = "3295333330922457057";
		String dtId = "3295333330922457056";
		String name = "";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		new DataTypeUrl(urlString);
	}

	@Test
	public void testGetDataType() {

		String name = "string";
		String dtmId = "3295333330922457057";
		FakeDataTypeManager manager = new FakeDataTypeManager(dtmId);
		FakeDataType dt = new FakeDataType(name, manager);

		DataTypeUrl dtUrl = new DataTypeUrl(dt);

		DataTypeManagerService service = new FakeDataTypeManagerService(manager);
		DataType actualDt = dtUrl.getDataType(service);
		assertEquals(dt, actualDt);
	}

	@Test
	public void testGetDataType_ByName() {

		String name = "string";
		String dtmId = "3295333330922457057";
		FakeDataTypeManager manager = new FakeDataTypeManager(dtmId);
		FakeDataType dt = new FakeDataType(name, manager);

		String dtId = ""; // no id; name only
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;
		DataTypeUrl dtUrl = new DataTypeUrl(urlString);

		DataTypeManagerService service = new FakeDataTypeManagerService(manager);
		DataType actualDt = dtUrl.getDataType(service);
		assertEquals(dt, actualDt);
	}

	@Test
	public void testEquals() {

		String name = "string";
		FakeDataType dt = new FakeDataType(name);

		DataTypeUrl dtUrl1 = new DataTypeUrl(dt);
		DataTypeUrl dtUrl2 = new DataTypeUrl(dt);
		assertEquals(dtUrl1, dtUrl2);

		FakeDataType otherDt = new FakeDataType("otherType");
		DataTypeUrl otherDtUrl = new DataTypeUrl(otherDt);
		assertNotEquals(dtUrl1, otherDtUrl);
	}

	@Test
	public void testHashCode() {

		String name = "string";
		FakeDataType dt = new FakeDataType(name);

		DataTypeUrl dtUrl1 = new DataTypeUrl(dt);
		DataTypeUrl dtUrl2 = new DataTypeUrl(dt);
		assertEquals(dtUrl1.hashCode(), dtUrl2.hashCode());

		FakeDataType otherDt = new FakeDataType("otherType");
		DataTypeUrl otherDtUrl = new DataTypeUrl(otherDt);
		assertNotEquals(dtUrl1.hashCode(), otherDtUrl.hashCode());
	}

	@Test
	public void testToString() {

		String dtmId = "3295333330922457057";
		String dtId = "3295333330922457056";
		String name = "string";
		String urlString = "datatype:/" + dtmId + "?uid=" + dtId + "&name=" + name;

		DataTypeUrl dtUrl = new DataTypeUrl(urlString);
		assertEquals(urlString, dtUrl.toString());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class FakeDataType extends TestDoubleDataType {

		private DataTypeManager manager = new FakeDataTypeManager();

		FakeDataType(String name) {
			super(name);
		}

		FakeDataType(String name, FakeDataTypeManager manager) {
			super(name);
			this.manager = manager;
			manager.addDataType(this);
		}

		@Override
		public DataTypeManager getDataTypeManager() {
			return manager;
		}
	}

	private class FakeDataTypeManager extends TestDoubleDataTypeManager {

		private UniversalID id;
		private List<DataType> types = new ArrayList<>();

		FakeDataTypeManager() {
			id = UniversalIdGenerator.nextID();
		}

		FakeDataTypeManager(String idString) {
			id = new UniversalID(Long.parseLong(idString));
		}

		void addDataType(DataType dt) {
			types.add(dt);
		}

		@Override
		public UniversalID getUniversalID() {
			return id;
		}

		@Override
		public DataType getDataType(DataTypePath path) {
			for (DataType dt : types) {
				if (dt.getName().equals(path.getDataTypeName())) {
					return dt;
				}
			}
			return null;
		}

		@Override
		public DataType findDataTypeForID(UniversalID datatypeID) {
			for (DataType dt : types) {
				if (dt.getUniversalID().equals(datatypeID)) {
					return dt;
				}
			}
			return null;
		}
	}

	private class FakeDataTypeManagerService extends TestDoubleDataTypeManagerService {

		private DataTypeManager manager;

		FakeDataTypeManagerService(DataTypeManager manager) {
			this.manager = manager;
		}

		@Override
		public DataTypeManager[] getDataTypeManagers() {
			return new DataTypeManager[] { manager };
		}
	}

}
