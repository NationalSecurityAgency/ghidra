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

import static org.junit.Assert.*;

import java.io.FileNotFoundException;
import java.io.InputStream;

import org.junit.Before;

import generic.test.AbstractGTest;
import ghidra.app.util.cparser.C.CParser;
import ghidra.util.Msg;
import resources.ResourceManager;

public abstract class AbstractCompositeImplBitFieldTest extends AbstractGTest {

	protected static final String C_SOURCE_FILE = "ghidra/app/util/cparser/bitfields.h";

	@Before
	public void setUp() throws Exception {

		DataTypeManager dataMgr = getDataTypeManager();
		if (dataMgr.getDataTypeCount(false) != 0) {
//			Msg.info(this, "Using previously parsed data types");
			return; // already have types
		}

		Msg.info(this, "Parsing data types from " + C_SOURCE_FILE);

		CParser parser = new CParser(dataMgr, true, null);

		try (InputStream is = ResourceManager.getResourceAsStream(C_SOURCE_FILE)) {
			if (is == null) {
				throw new FileNotFoundException("Resource not found: " + C_SOURCE_FILE);
			}
			Msg.debug(this, "Parsing C headers from " + C_SOURCE_FILE);
			parser.parse(is);
		}
	}

	protected class MyDataTypeManager extends StandAloneDataTypeManager {
		MyDataTypeManager(String name, DataOrganization dataOrg) {
			super(name);
			this.dataOrganization = dataOrg;
		}
	}

	abstract DataTypeManager getDataTypeManager();

	Structure getStructure(String name) {
		DataType dataType = getDataTypeManager().getDataType("/" + name);
		assertTrue("Data type not found: " + name, dataType instanceof Structure);
		return (Structure) dataType;
	}

	Union getUnion(String name) {
		DataType dataType = getDataTypeManager().getDataType("/" + name);
		assertTrue("Data type not found: " + name, dataType instanceof Union);
		return (Union) dataType;
	}

}
