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
package ghidra.app.plugin.core.debug.gui.thread;

import java.io.IOException;

import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;

@Category(NightlyCategory.class)
public class DebuggerThreadsProviderObjectTest extends DebuggerThreadsProviderTest {

	protected SchemaContext ctx;

	@Override
	protected void createTrace(String langID) throws IOException {
		super.createTrace(langID);
		try {
			activateObjectsMode();
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void useTrace(Trace trace) {
		super.useTrace(trace);
		try {
			activateObjectsMode();
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	public void activateObjectsMode() throws Exception {
		// NOTE the use of index='1' allowing object-based managers to ID unique path
		ctx = XmlSchemaContext.deserialize("" + //
			"<context>" + //
			"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <attribute name='Processes' schema='ProcessContainer' />" + //
			"    </schema>" + //
			"    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element index='1' schema='Process' />" + // <---- NOTE HERE
			"    </schema>" + //
			"    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <attribute name='Threads' schema='ThreadContainer' />" + //
			"    </schema>" + //
			"    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Thread' />" + //
			"    </schema>" + //
			"    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='Thread' />" + //
			"    </schema>" + //
			"</context>");

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}
}
