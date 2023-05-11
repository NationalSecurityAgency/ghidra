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
package ghidra.trace.database.memory;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.lang.LanguageID;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.LanguageTestWatcher.TestLanguage;

public class DBTraceMemoryManagerObjectRegistersPerFrameBETest
		extends AbstractDBTraceMemoryManagerRegistersTest {

	protected SchemaContext ctx;

	@Before
	public void setUpObjectsMode() throws Exception {
		ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Regions' schema='RegionContainer' />
				        <attribute name='Threads' schema='ThreadContainer' />
				    </schema>
				    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Region' />
				    </schema>
				    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='MemoryRegion' />
				    </schema>
				    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Thread' />
				    </schema>
				    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Aggregate' />
				        <interface name='Thread' />
				        <attribute name='Stack' schema='Stack' />
				    </schema>
				    <schema name='Stack' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <interface name='Stack' />
				        <element schema='Frame' />
				    </schema>
				    <schema name='Frame' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <interface name='StackFrame' />
				        <interface name='RegisterContainer' />
				        <element schema='Register' />
				    </schema>
				    <schema name='Register' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Register' />
				    </schema>
				</context>
				""");

		try (Transaction tx = b.startTransaction()) {
			b.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	@Override
	protected TraceThread getOrAddThread(String name, long creationSnap) {
		TraceThread thread = super.getOrAddThread(name, creationSnap);
		TraceObject obj = ((TraceObjectThread) thread).getObject();
		TraceObject objRegs = b.trace.getObjectManager()
				.createObject(obj.getCanonicalPath().extend(PathUtils.parse("Stack[0]")));
		objRegs.insert(Lifespan.ALL, ConflictResolution.DENY);
		return thread;
	}

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("Toy:BE:64:default");
	}

	@Override
	protected boolean isRegistersPerFrame() {
		return true;
	}

	@Test
	@TestLanguage("Toy:BE:32:builder")
	public void testRegisterBits() throws Exception {
		runTestRegisterBits(b.host);
	}
}
