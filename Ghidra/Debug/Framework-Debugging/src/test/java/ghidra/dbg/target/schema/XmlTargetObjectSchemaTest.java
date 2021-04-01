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

import java.io.IOException;

import org.jdom.JDOMException;
import org.junit.Test;

import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.*;

public class XmlTargetObjectSchemaTest {
	protected static final String SCHEMA_XML = "" +
		"<context>\n" +
		"    <schema name=\"root\" canonical=\"yes\" elementResync=\"NEVER\" attributeResync=\"ONCE\">\n" +
		"        <interface name=\"Process\" />\n" +
		"        <interface name=\"Interpreter\" />\n" +
		"        <element index=\"reserved\" schema=\"VOID\" />\n" +
		"        <element schema=\"down1\" />\n" +
		"        <attribute name=\"some_int\" schema=\"INT\" />\n" +
		"        <attribute name=\"some_object\" schema=\"OBJECT\" required=\"yes\" fixed=\"yes\" hidden=\"yes\" />\n" +
		"        <attribute schema=\"ANY\" hidden=\"yes\" />\n" +
		"    </schema>\n" +
		"    <schema name=\"down1\" elementResync=\"ALWAYS\" attributeResync=\"ALWAYS\">\n" +
		"        <element schema=\"OBJECT\" />\n" +
		"        <attribute schema=\"VOID\" fixed=\"yes\" hidden=\"yes\" />\n" +
		"    </schema>\n" +
		"</context>";

	protected static final DefaultSchemaContext CTX = new DefaultSchemaContext();
	protected static final SchemaName NAME_ROOT = new SchemaName("root");
	protected static final SchemaName NAME_DOWN1 = new SchemaName("down1");
	protected static final TargetObjectSchema SCHEMA_ROOT = CTX.builder(NAME_ROOT)
			.addInterface(TargetProcess.class)
			.addInterface(TargetInterpreter.class)
			.setCanonicalContainer(true)
			.addElementSchema("reserved", EnumerableTargetObjectSchema.VOID.getName(), null)
			.addElementSchema("", NAME_DOWN1, null)
			.setElementResyncMode(ResyncMode.NEVER)
			.addAttributeSchema(new DefaultAttributeSchema("some_int",
				EnumerableTargetObjectSchema.INT.getName(), false, false, false), null)
			.addAttributeSchema(new DefaultAttributeSchema("some_object",
				EnumerableTargetObjectSchema.OBJECT.getName(), true, true, true), null)
			.setAttributeResyncMode(ResyncMode.ONCE)
			.buildAndAdd();
	protected static final TargetObjectSchema SCHEMA_DOWN1 = CTX.builder(NAME_DOWN1)
			.setElementResyncMode(ResyncMode.ALWAYS)
			.setDefaultAttributeSchema(AttributeSchema.DEFAULT_VOID)
			.setAttributeResyncMode(ResyncMode.ALWAYS)
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
}
