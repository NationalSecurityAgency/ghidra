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
package ghidra.app.plugin.core.debug.gui.memory;

import java.io.IOException;

import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.util.database.UndoableTransaction;

@Category(NightlyCategory.class)
public class DebuggerRegionsProviderObjectTest extends DebuggerRegionsProviderTest {

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

	public void activateObjectsMode() throws Exception {
		ctx = XmlSchemaContext.deserialize("" + //
			"<context>" + //
			"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <attribute name='Memory' schema='RegionContainer' />" + //
			"    </schema>" + //
			"    <schema name='RegionContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Region' />" + //
			"    </schema>" + //
			"    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='MemoryRegion' />" + //
			"    </schema>" + //
			"</context>");

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}
}
