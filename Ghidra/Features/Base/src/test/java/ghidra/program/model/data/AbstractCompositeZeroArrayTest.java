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

import org.junit.Before;

/**
 * This test uses the CParser to parse all datatypes defined by zeroarray.h.
 * The parse process entails building up the composite types using the various 
 * "Impl" datatypes followed by their being resolved into the associated datatype
 * manager where DB datatypes will be established.
 * <br>
 * When fetching datatypes from the datatype manager they will naturally be 
 * returned as DB datatypes when applicable (see {@link #getStructure(String)} and 
 * {@link #getUnion(String)}).  If the test class name contains "Impl" a deep copy 
 * will be performed on datatypes to return as an non-DB Impl datatype. 
 */
public abstract class AbstractCompositeZeroArrayTest extends AbstractCompositeTest {

	protected static final String C_SOURCE_FILE = "ghidra/app/util/cparser/zeroarray.h";

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		parseCHeaderFile(C_SOURCE_FILE);
	}
}
