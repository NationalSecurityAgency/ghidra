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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.io.IOException;

import db.Transaction;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectKeyPath;

public class DebuggerLogicalBreakpointServiceObjectTest
		extends DebuggerLogicalBreakpointServiceTest {

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
		// NOTE the use of index='...' allowing object-based managers to ID unique path
		// TODO: I guess this'll burn down if the naming scheme changes....
		int index = tb.trace.getName().startsWith("[3]") ? 3 : 1;
		ctx = XmlSchemaContext.deserialize(String.format("""
				<context>
				    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Processes' schema='ProcessContainer' />
				    </schema>
				    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element index='%d' schema='Process' /> <!-- NOTE HERE -->
				    </schema>
				    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
				        <interface name='Aggregate' />
				        <attribute name='Threads' schema='ThreadContainer' />
				        <attribute name='Memory' schema='RegionContainer' />
				        <attribute name='Breakpoints' schema='BreakpointContainer' />
				    </schema>
				    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Thread' />
				    </schema>
				    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Aggregate' />
				        <interface name='Thread' />
				        <attribute name='Registers' schema='Registers' />
				    </schema>
				    <schema name='Registers' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='RegisterBank' />
				        <interface name='RegisterContainer' />
				    </schema>
				    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Region' />
				    </schema>
				    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='MemoryRegion' />
				    </schema>
				    <schema name='BreakpointContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <interface name='BreakpointSpecContainer' />
				        <element schema='Breakpoint' />
				    </schema>
				    <schema name='Breakpoint' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='BreakpointSpec' />
				        <interface name='BreakpointLocation' />
				    </schema>
				</context>
				""", index));

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
			tb.trace.getObjectManager()
					.createObject(
						TraceObjectKeyPath.of("Processes", "[" + index + "]", "Breakpoints"));
		}
	}
}
