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

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Test;

import ghidra.dbg.agent.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.program.model.address.AddressFactory;

public class TargetObjectSchemaValidationTest {
	protected DefaultSchemaContext ctx = new DefaultSchemaContext();

	protected SchemaName nameRoot = new SchemaName("Root");

	protected SchemaName nameDown1 = new SchemaName("Down1");
	protected TargetObjectSchema schemaDown1 = ctx.builder(nameDown1)
			.buildAndAdd();

	protected SchemaName nameWReq = new SchemaName("WithRequired");
	protected TargetObjectSchema schemaWReq = ctx.builder(nameWReq)
			.addAttributeSchema(new DefaultAttributeSchema("req",
				EnumerableTargetObjectSchema.ANY.getName(), true, false, false), null)
			.buildAndAdd();

	protected AbstractDebuggerObjectModel model = new AbstractDebuggerObjectModel() {
		@Override
		public CompletableFuture<? extends TargetObject> fetchModelRoot() {
			fail();
			return null;
		}

		@Override
		public AddressFactory getAddressFactory() {
			fail();
			return null;
		}
	};

	@Test
	public void testAttributeSchemaAssignment() {
		TargetObjectSchema schemaRoot = ctx.builder(nameRoot)
				.addAttributeSchema(new DefaultTargetObjectSchema.DefaultAttributeSchema("my_attr",
					nameDown1, false, false, false), null)
				.buildAndAdd();

		DefaultTargetModelRoot root = new DefaultTargetModelRoot(model, "Root", schemaRoot);

		DefaultTargetObject<?, ?> control =
			new DefaultTargetObject<>(model, root, "control", "Default");
		assertNotEquals(schemaDown1, control.getSchema());

		DefaultTargetObject<?, ?> down1 =
			new DefaultTargetObject<>(model, root, "my_attr", "Default");

		assertEquals(schemaDown1, down1.getSchema());
	}

	@Test
	public void testElementSchemaAssignment() {
		TargetObjectSchema schemaRoot = ctx.builder(nameRoot)
				.addElementSchema("1", nameDown1, null)
				.buildAndAdd();

		DefaultTargetModelRoot root = new DefaultTargetModelRoot(model, "Root", schemaRoot);

		DefaultTargetObject<?, ?> control =
			new DefaultTargetObject<>(model, root, "[0]", "Default");
		assertNotEquals(schemaDown1, control.getSchema());

		DefaultTargetObject<TargetObject, TargetObject> down1 =
			new DefaultTargetObject<>(model, root, "[1]", "Default");

		assertEquals(schemaDown1, down1.getSchema());
	}

	static class ValidatedModelRoot extends DefaultTargetModelRoot {
		public ValidatedModelRoot(AbstractDebuggerObjectModel model, String typeHint,
				TargetObjectSchema schema) {
			super(model, typeHint, schema);
		}

		@Override
		public boolean enforcesStrictSchema() {
			return true;
		}
	}

	static class ValidatedObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public ValidatedObject(AbstractDebuggerObjectModel model, TargetObject parent, String key,
				TargetObjectSchema schema) {
			super(model, parent, key, "Object", schema);
		}

		public ValidatedObject(AbstractDebuggerObjectModel model, TargetObject parent, String key) {
			super(model, parent, key, "Object");
		}

		@Override
		public boolean enforcesStrictSchema() {
			return true;
		}
	}

	@Test
	public void testInterfaceValidation() {
		TargetObjectSchema schemaRoot = ctx.builder(nameRoot)
				.addInterface(TargetAggregate.class)
				.buildAndAdd();

		schemaRoot.validateTypeAndInterfaces(new ValidatedModelRoot(model, "Root", schemaRoot),
			List.of(), null, true);
		// pass
	}

	@Test(expected = AssertionError.class)
	public void testInterfaceValidationErr() {
		TargetObjectSchema schemaRoot = ctx.builder(nameRoot)
				.addInterface(TargetProcess.class)
				.buildAndAdd();

		schemaRoot.validateTypeAndInterfaces(new ValidatedModelRoot(model, "Root", schemaRoot),
			List.of(), null, true);
	}

	protected ValidatedModelRoot createRootAttrWReq() {
		TargetObjectSchema schemaRoot = ctx.builder(nameRoot)
				.addAttributeSchema(new DefaultTargetObjectSchema.DefaultAttributeSchema("my_attr",
					nameWReq, false, false, false), null)
				.buildAndAdd();
		return new ValidatedModelRoot(model, "Root", schemaRoot);
	}

	protected ValidatedModelRoot createRootElemWReq() {
		TargetObjectSchema schemaRoot = ctx.builder(nameRoot)
				.addElementSchema("1", nameWReq, null)
				.buildAndAdd();
		return new ValidatedModelRoot(model, "Root", schemaRoot);
	}

	protected DefaultTargetObject<?, ?> createWReqCorrect(TargetObject root, String name) {
		DefaultTargetObject<?, ?> wreq =
			new DefaultTargetObject<>(model, root, name, "Default");

		wreq.changeAttributes(List.of(), Map.of("req", "Hello!"), "Initialized");
		return wreq;
	}

	protected ValidatedObject createWReqIncorrect(TargetObject root, String name) {
		ValidatedObject wreq = new ValidatedObject(model, root, name);
		return wreq;
	}

	@Test
	public void testAttributeValidationAtInsertViaSetAttributes() {
		DefaultTargetModelRoot root = createRootAttrWReq();
		DefaultTargetObject<?, ?> wreq = createWReqCorrect(root, "my_attr");
		root.setAttributes(List.of(wreq), Map.of(), "Initialized");
	}

	@Test(expected = AssertionError.class)
	public void testAttributeValidationViaFetchAttributesErr()
			throws InterruptedException, ExecutionException {
		DefaultTargetModelRoot root = createRootAttrWReq();
		DefaultTargetObject<?, ?> wreq = createWReqIncorrect(root, "my_attr");
		try {
			wreq.fetchAttributes().get();
		}
		catch (ExecutionException e) {
			ExceptionUtils.rethrow(e.getCause());
		}
	}

	@Test
	public void testAttributeValidationAtInsertViaChangeAttributes() {
		DefaultTargetModelRoot root = createRootAttrWReq();
		DefaultTargetObject<?, ?> wreq = createWReqCorrect(root, "my_attr");
		root.changeAttributes(List.of(), List.of(wreq), Map.of(), "Initialized");
	}

	@Test
	public void testAttributeValidationAtInsertViaSetElements() {
		DefaultTargetModelRoot root = createRootElemWReq();
		DefaultTargetObject<?, ?> wreq = createWReqCorrect(root, "[1]");
		root.setElements(List.of(wreq), Map.of(), "Initialized");
	}

	@Test
	public void testAttributeValidationAtInsertViaChangeElements() {
		DefaultTargetModelRoot root = createRootElemWReq();
		DefaultTargetObject<?, ?> wreq = createWReqCorrect(root, "[1]");
		root.changeElements(List.of(), List.of(wreq), Map.of(), "Initialized");
	}

	@Test(expected = AssertionError.class)
	public void testValidateRequiredAttributeViaSetErr() {
		TargetObjectSchema schema = ctx.builder(new SchemaName("test"))
				.addAttributeSchema(new DefaultAttributeSchema("req",
					EnumerableTargetObjectSchema.ANY.getName(), true, false, false), null)
				.buildAndAdd();
		ValidatedObject obj = new ValidatedObject(model, null, "Test", schema);

		obj.setAttributes(List.of(), Map.of("req", "Hello"), "Initialized");
		obj.setAttributes(List.of(), Map.of(), "Test");
	}

	@Test(expected = AssertionError.class)
	public void testValidateRequiredAttributeViaChangeErr() {
		TargetObjectSchema schema = ctx.builder(new SchemaName("test"))
				.addAttributeSchema(new DefaultAttributeSchema("req",
					EnumerableTargetObjectSchema.ANY.getName(), true, false, false), null)
				.buildAndAdd();
		ValidatedObject obj = new ValidatedObject(model, null, "Test", schema);

		obj.setAttributes(List.of(), Map.of("req", "Hello"), "Initialized");
		obj.changeAttributes(List.of("req"), List.of(), Map.of(), "Test");
	}

	@Test(expected = AssertionError.class)
	public void testValidateFixedAttributeViaSetErr() {
		TargetObjectSchema schema = ctx.builder(new SchemaName("test"))
				.addAttributeSchema(new DefaultAttributeSchema("fix",
					EnumerableTargetObjectSchema.ANY.getName(), false, true, false), null)
				.buildAndAdd();
		ValidatedObject obj = new ValidatedObject(model, null, "Test", schema);

		obj.setAttributes(List.of(), Map.of("fix", "Hello"), "Initialized");
		obj.setAttributes(List.of(), Map.of("fix", "World"), "Test");
	}

	@Test(expected = AssertionError.class)
	public void testValidateFixedAttributeViaChangeErr() {
		TargetObjectSchema schema = ctx.builder(new SchemaName("test"))
				.addAttributeSchema(new DefaultAttributeSchema("fix",
					EnumerableTargetObjectSchema.ANY.getName(), false, true, false), null)
				.buildAndAdd();
		ValidatedObject obj = new ValidatedObject(model, null, "Test", schema);

		obj.setAttributes(List.of(), Map.of("fix", "Hello"), "Initialized");
		// Removal of fixed attr also forbidden after it's set
		obj.changeAttributes(List.of("fix"), List.of(), Map.of(), "Test");
	}

	ValidatedObject createRepleteValidatedObject() {
		TargetObjectSchema schema = ctx.builder(new SchemaName("test"))
				.addAttributeSchema(new DefaultAttributeSchema("_display",
					EnumerableTargetObjectSchema.STRING.getName(), true, false, false), null)
				.addAttributeSchema(new DefaultAttributeSchema("int",
					EnumerableTargetObjectSchema.INT.getName(), false, false, false), null)
				.addAttributeSchema(new DefaultAttributeSchema("obj",
					EnumerableTargetObjectSchema.OBJECT.getName(), false, false, false), null)
				.setDefaultAttributeSchema(AttributeSchema.DEFAULT_VOID)
				.buildAndAdd();
		ValidatedObject obj = new ValidatedObject(model, null, "Test", schema);
		return obj;
	}

	@Test
	public void testValidateAttributeTypesViaSet() {
		ValidatedObject obj = createRepleteValidatedObject();
		obj.setAttributes(List.of(), Map.of(
			"_display", "Hello",
			"int", 5),
			"Test");
		obj.setAttributes(List.of(), Map.of(
			"_display", "World",
			"int", 6),
			"Test");
	}

	@Test
	public void testValidateAttributeTypesViaChange() {
		ValidatedObject obj = createRepleteValidatedObject();
		obj.changeAttributes(List.of(), Map.of("int", 5), "Test");
		obj.changeAttributes(List.of(), Map.of("int", 6), "Test");
	}

	@Test(expected = AssertionError.class)
	public void testValidateAttributeTypesViaSetErr() {
		ValidatedObject obj = createRepleteValidatedObject();
		obj.setAttributes(List.of(), Map.of(
			"_display", "World",
			"int", 7.0),
			"Test");
	}

	@Test(expected = AssertionError.class)
	public void testValidateAttributeTypesViaChangeErr() {
		ValidatedObject obj = createRepleteValidatedObject();
		obj.changeAttributes(List.of(), Map.of("int", 7.0), "Test");
	}
}
