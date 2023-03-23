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
package ghidra.trace.database.breakpoint;

import org.junit.Before;

import db.Transaction;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;

public class DBTraceBreakpointManagerObjectTest extends DBTraceBreakpointManagerTest {

	protected SchemaContext ctx;

	@Before
	public void setUpObjectsMode() throws Exception {
		ctx = XmlSchemaContext.deserialize("" + //
			"<context>" + //
			"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <interface name='Process' />" + //
			"        <attribute name='Threads' schema='ThreadContainer' />" + //
			"        <attribute name='Breakpoints' schema='BreakpointContainer' />" + //
			"    </schema>" + //
			"    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Thread' />" + //
			"    </schema>" + //
			"    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='Thread' />" + //
			"    </schema>" + //
			"    <schema name='BreakpointContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Breakpoint' />" + //
			"    </schema>" + //
			"    <schema name='Breakpoint' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='BreakpointSpec' />" + //
			"        <interface name='BreakpointLocation' />" + //
			"    </schema>" + //
			"</context>");

		try (Transaction tx = b.startTransaction()) {
			b.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	@Override
	public void testSplitAndSet() throws Exception {
		// This method is not supported in objects mode.
	}
}
