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
package ghidra.dbg.target.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.jdom.JDOMException;
import org.junit.Ignore;
import org.junit.Test;

import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.DefaultTraceObjectSchema.DefaultAttributeSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.*;
import ghidra.trace.model.thread.TraceProcess;

public class XmlTargetObjectSchemaTest {
	protected static final String SCHEMA_XML =
		// Do not line-wrap or serialize test will fail
		"""
				<context>
				    <schema name="root" canonical="yes">
				        <interface name="Process" />
				        <element index="reserved" schema="VOID" />
				        <element schema="down1" />
				        <attribute name="some_int" schema="INT" />
				        <attribute name="some_object" schema="OBJECT" required="yes" fixed="yes" hidden="yes" />
				        <attribute-alias from="_int" to="some_int" />
				    </schema>
				    <schema name="down1">
				        <attribute schema="VOID" fixed="yes" hidden="yes" />
				    </schema>
				</context>"""; // Cannot have a final new-line or serialize test will fail

	protected static final DefaultSchemaContext CTX = new DefaultSchemaContext();
	protected static final SchemaName NAME_ROOT = new SchemaName("root");
	protected static final SchemaName NAME_DOWN1 = new SchemaName("down1");
	protected static final TraceObjectSchema SCHEMA_ROOT = CTX.builder(NAME_ROOT)
			.addInterface(TraceProcess.class)
			.setCanonicalContainer(true)
			.addElementSchema("reserved", PrimitiveTraceObjectSchema.VOID.getName(), null)
			.addElementSchema("", NAME_DOWN1, null)
			.addAttributeSchema(new DefaultAttributeSchema("some_int",
				PrimitiveTraceObjectSchema.INT.getName(), false, false, Hidden.FALSE), null)
			.addAttributeSchema(new DefaultAttributeSchema("some_object",
				PrimitiveTraceObjectSchema.OBJECT.getName(), true, true, Hidden.TRUE), null)
			.addAttributeAlias("_int", "some_int", null)
			.buildAndAdd();
	protected static final TraceObjectSchema SCHEMA_DOWN1 = CTX.builder(NAME_DOWN1)
			.setDefaultAttributeSchema(AttributeSchema.DEFAULT_VOID)
			.buildAndAdd();

	@Test
	public void testSerialize() {
		String serialized =
			XmlSchemaContext.serialize(CTX).replace("\t", "    ").replace("\r", "").trim();
		assertEquals(SCHEMA_XML, serialized);
	}

	@Test
	public void testDeserialize() throws JDOMException, IOException {
		SchemaContext result = XmlSchemaContext.deserialize(SCHEMA_XML);
		assertEquals(CTX, result);
	}

	@Test
	@Ignore("Actually, null is what's intended, but that design needs fixing.")
	public void testSearchWithMultipleImpls() throws Exception {
		SchemaContext ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name="root">
				        <interface name="Aggregate" />
				        <attribute name="Watches" schema="WatchContainer" />
				        <attribute name="Breaks" schema="BreakContainer" />
				    </schema>
				    <schema name="WatchContainer" canonical="yes">
				        <element schema="Watch" />
				    </schema>
				    <schema name="Watch">
				        <interface name="BreakpointSpec" />
				        <interface name="BreakpointLocation" />
				    </schema>
				    <schema name="BreakContainer" canonical="yes">
				        <element schema="Break" />
				    </schema>
				    <schema name="Break">
				        <interface name="BreakpointSpec" />
				        <interface name="BreakpointLocation" />
				    </schema>
				</context>
				""");

		KeyPath found = ctx.getSchema(new SchemaName("root"))
				.searchForSuitable(TraceBreakpointLocation.class, KeyPath.ROOT);
		assertNotNull(found);
	}
}
