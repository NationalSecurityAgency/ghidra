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

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import ghidra.dbg.agent.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;

public class AnnotatedTargetObjectSchemaTest {

	protected static SchemaBuilder addBasicAttributes(SchemaBuilder builder) {
		builder.addAttributeSchema(new DefaultAttributeSchema("_value",
			EnumerableTargetObjectSchema.ANY.getName(), false, false, true), null);
		builder.addAttributeSchema(new DefaultAttributeSchema("_type",
			EnumerableTargetObjectSchema.STRING.getName(), false, false, true), null);
		builder.addAttributeSchema(new DefaultAttributeSchema("_display",
			EnumerableTargetObjectSchema.STRING.getName(), false, false, true), null);
		builder.addAttributeSchema(new DefaultAttributeSchema("_short_display",
			EnumerableTargetObjectSchema.STRING.getName(), false, false, true), null);
		builder.addAttributeSchema(new DefaultAttributeSchema("_kind",
			EnumerableTargetObjectSchema.STRING.getName(), false, true, true), null);
		builder.addAttributeSchema(new DefaultAttributeSchema("_order",
			EnumerableTargetObjectSchema.INT.getName(), false, false, true), null);
		builder.addAttributeSchema(new DefaultAttributeSchema("_modified",
			EnumerableTargetObjectSchema.BOOL.getName(), false, false, true), null);
		return builder;
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootPlain extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootPlain(AbstractDebuggerObjectModel model, String typeHint) {
			super(model, typeHint);
		}
	}

	@Test
	public void testAnnotatedRootSchemaPlain() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema = ctx.getSchemaForClass(TestAnnotatedTargetRootPlain.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.addInterface(TargetAggregate.class) // Inherited from root
				.build();
		assertEquals(exp, schema);
	}

	@TargetObjectSchemaInfo(elements = @TargetElementType(type = Void.class))
	static class TestAnnotatedTargetRootNoElems extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootNoElems(AbstractDebuggerObjectModel model, String typeHint) {
			super(model, typeHint);
		}
	}

	@Test
	public void testAnnotatedRootSchemaNoElems() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema = ctx.getSchemaForClass(TestAnnotatedTargetRootNoElems.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.addInterface(TargetAggregate.class) // Inherited from root
				.setDefaultElementSchema(EnumerableTargetObjectSchema.VOID.getName())
				.build();
		assertEquals(exp, schema);
	}

	@TargetObjectSchemaInfo(name = "Process")
	static class TestAnnotatedTargetProcessStub
			extends DefaultTargetObject<TargetObject, TargetObject>
			implements TargetProcess {
		public TestAnnotatedTargetProcessStub(AbstractDebuggerObjectModel model,
				TargetObject parent, String key, String typeHint) {
			super(model, parent, key, typeHint);
		}
	}

	@TargetObjectSchemaInfo(name = "Root")
	static class TestAnnotatedTargetRootOverriddenFetchElems extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootOverriddenFetchElems(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@Override
		public CompletableFuture<? extends Map<String, TestAnnotatedTargetProcessStub>> fetchElements(
				boolean refresh) {
			return null; // Doesn't matter
		}
	}

	@Test
	public void testAnnotatedRootSchemaOverridenFetchElems() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema =
			ctx.getSchemaForClass(TestAnnotatedTargetRootOverriddenFetchElems.class);

		SchemaName schemaProc = ctx.nameFromClass(TestAnnotatedTargetProcessStub.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.addInterface(TargetAggregate.class)
				.setDefaultElementSchema(schemaProc)
				.build();
		assertEquals(exp, schema);
		assertEquals("Root", schema.getName().toString());
	}

	@TargetObjectSchemaInfo(name = "ProcessContainer")
	static class TestAnnotatedProcessContainer
			extends DefaultTargetObject<TestAnnotatedTargetProcessStub, TargetObject> {
		public TestAnnotatedProcessContainer(AbstractDebuggerObjectModel model, TargetObject parent,
				String key, String typeHint) {
			super(model, parent, key, typeHint);
		}
	}

	@Test
	public void testAnnotatedSubSchemaElemsByParam() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema = ctx.getSchemaForClass(TestAnnotatedProcessContainer.class);

		SchemaName schemaProc = ctx.nameFromClass(TestAnnotatedTargetProcessStub.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.setDefaultElementSchema(schemaProc)
				.build();
		assertEquals(exp, schema);
	}

	@TargetObjectSchemaInfo(name = "Process")
	static class TestAnnotatedTargetProcessParam
			extends DefaultTargetObject<TargetObject, TargetObject>
			implements TargetProcess {
		public TestAnnotatedTargetProcessParam(AbstractDebuggerObjectModel model,
				TargetObject parent, String key, String typeHint) {
			super(model, parent, key, typeHint);
		}
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootWithAnnotatedAttrs extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootWithAnnotatedAttrs(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@TargetAttributeType(name = "int_attribute")
		public int getSomeIntAttribute() {
			return 0; // Doesn't matter
		}

		@TargetAttributeType
		public TestAnnotatedTargetProcessParam getSomeObjectAttribute() {
			return null; // Doesn't matter
		}
	}

	@Test
	public void testAnnotatedRootSchemaWithAnnotatedAttrs() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema =
			ctx.getSchemaForClass(TestAnnotatedTargetRootWithAnnotatedAttrs.class);

		SchemaName schemaProc = ctx.nameFromClass(TestAnnotatedTargetProcessParam.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.addInterface(TargetAggregate.class)
				.addAttributeSchema(new DefaultAttributeSchema("int_attribute",
					EnumerableTargetObjectSchema.INT.getName(), false, false, false), null)
				.addAttributeSchema(new DefaultAttributeSchema("some_object_attribute",
					schemaProc, false, false, false), null)
				.build();
		assertEquals(exp, schema);
		assertEquals("TestAnnotatedTargetRootWithAnnotatedAttrs", schema.getName().toString());
	}

	@TargetObjectSchemaInfo(
		attributes = {
			@TargetAttributeType(type = Void.class),
			@TargetAttributeType(name = "some_int_attribute", type = Integer.class),
			@TargetAttributeType(
				name = "some_object_attribute",
				type = TestAnnotatedTargetProcessStub.class)
		},
		elements = {
			@TargetElementType(index = "reserved", type = Void.class)
		})
	static class TestAnnotatedTargetRootWithListedAttrs extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootWithListedAttrs(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}
	}

	@Test
	public void testAnnotatedRootSchemaWithListedAttrs() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema =
			ctx.getSchemaForClass(TestAnnotatedTargetRootWithListedAttrs.class);

		SchemaName schemaProc = ctx.nameFromClass(TestAnnotatedTargetProcessStub.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.addInterface(TargetAggregate.class)
				.setDefaultAttributeSchema(new DefaultAttributeSchema("",
					EnumerableTargetObjectSchema.VOID.getName(), false, false, false))
				.addAttributeSchema(new DefaultAttributeSchema("some_int_attribute",
					EnumerableTargetObjectSchema.INT.getName(), false, false, false), null)
				.addAttributeSchema(new DefaultAttributeSchema("some_object_attribute",
					schemaProc, false, false, false), null)
				.addElementSchema("reserved", EnumerableTargetObjectSchema.VOID.getName(), null)
				.build();
		assertEquals(exp, schema);
		assertEquals("TestAnnotatedTargetRootWithListedAttrs", schema.getName().toString());
	}

	@TargetObjectSchemaInfo(elementResync = ResyncMode.ONCE, attributeResync = ResyncMode.ALWAYS)
	static class TestAnnotatedTargetRootWithResyncModes extends DefaultTargetModelRoot {

		public TestAnnotatedTargetRootWithResyncModes(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}
	}

	@Test
	public void testAnnotatedRootWithResyuncModes() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		TargetObjectSchema schema =
			ctx.getSchemaForClass(TestAnnotatedTargetRootWithResyncModes.class);

		TargetObjectSchema exp = addBasicAttributes(ctx.builder(schema.getName()))
				.addInterface(TargetAggregate.class)
				.setElementResyncMode(ResyncMode.ONCE)
				.setAttributeResyncMode(ResyncMode.ALWAYS)
				.build();
		assertEquals(exp, schema);
	}

	static class NotAPrimitive {
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootWithAnnotatedAttrsBadType extends DefaultTargetModelRoot {

		public TestAnnotatedTargetRootWithAnnotatedAttrsBadType(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@TargetAttributeType
		public NotAPrimitive getSomeErrAttribute() {
			return null; // Doesn't matter
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAnnotatedRootSchemaWithAnnotatedAttrsBadType() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(TestAnnotatedTargetRootWithAnnotatedAttrsBadType.class);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNotAnnotated() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(DefaultTargetObject.class);
	}

	static class Dummy {
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootWithAnnotatedAttrsNonUnique<T extends Dummy & TargetProcess & TargetInterpreter>
			extends DefaultTargetModelRoot {

		public TestAnnotatedTargetRootWithAnnotatedAttrsNonUnique(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@TargetAttributeType
		public T getSomeErrAttribute() {
			return null; // Doesn't matter
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAnnotatedRootWithAnnotatedAttrsNonUnique() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(TestAnnotatedTargetRootWithAnnotatedAttrsNonUnique.class);
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootWithElemsNonUnique<T extends Dummy & TargetProcess & TargetInterpreter>
			extends DefaultTargetModelRoot {

		public TestAnnotatedTargetRootWithElemsNonUnique(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@Override
		public CompletableFuture<? extends Map<String, ? extends T>> fetchElements(
				boolean refresh) {
			return null; // Doesn't matter
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAnnotatedRootWithElemsNonUnique() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(TestAnnotatedTargetRootWithElemsNonUnique.class);
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootWithAnnotatedAttrsBadName extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootWithAnnotatedAttrsBadName(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@TargetAttributeType
		public int get() {
			return 0; // Doesn't matter
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAnnotatedRootSchemaWithAnnotatedAttrsBadName() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(TestAnnotatedTargetRootWithAnnotatedAttrsBadName.class);
	}

	@TargetObjectSchemaInfo
	static class TestAnnotatedTargetRootWithAnnotatedAttrsBadGetter extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootWithAnnotatedAttrsBadGetter(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}

		@TargetAttributeType
		public int getSomeIntAttribute(boolean bogus) {
			return 0; // Doesn't matter
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAnnotatedRootSchemaWithAnnotatedAttrsBadGetter() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(TestAnnotatedTargetRootWithAnnotatedAttrsBadGetter.class);
	}

	@TargetObjectSchemaInfo(
		attributes = @TargetAttributeType(name = "some_attr", type = NotAPrimitive.class))
	static class TestAnnotatedTargetRootWithListedAttrsBadType extends DefaultTargetModelRoot {
		public TestAnnotatedTargetRootWithListedAttrsBadType(AbstractDebuggerObjectModel model,
				String typeHint) {
			super(model, typeHint);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAnnotatedRootSchemaWithListAttrsBadType() {
		AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
		ctx.getSchemaForClass(TestAnnotatedTargetRootWithListedAttrsBadType.class);
	}
}
