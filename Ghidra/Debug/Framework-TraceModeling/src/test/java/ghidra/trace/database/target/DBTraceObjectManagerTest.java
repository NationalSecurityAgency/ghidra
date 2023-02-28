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
package ghidra.trace.database.target;

import static org.junit.Assert.*;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathPredicates;
import ghidra.dbg.util.PathUtils;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStore;

public class DBTraceObjectManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	public static final String XML_CTX = """
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='curTarget' schema='Target' />
			        <attribute name='Targets' schema='TargetContainer' />
			    </schema>
			    <schema name='TargetContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Target' />
			    </schema>
			    <schema name='Target' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Process' />
			        <attribute name='self' schema='Target' />
			        <attribute name='Threads' schema='ThreadContainer' />
			        <attribute name='Memory' schema='Memory' />
			    </schema>
			    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Thread' />
			    </schema>
			    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Thread' />
			        <interface name='Aggregate' />
			        <attribute name='Registers' schema='RegisterContainer' />
			    </schema>
			    <schema name='RegisterContainer' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='RegisterContainer' />
			        <attribute name='User' schema='RegisterGroup' />
			        <attribute name='Float' schema='RegisterGroup' />
			    </schema>
			    <schema name='RegisterGroup' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Register' />
			    </schema>
			    <schema name='Register' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Register' />
			    </schema>
			    <schema name='Memory' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Region' />
			    </schema>
			    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='MemoryRegion' />
			    </schema>
			</context>
			""";
	protected ToyDBTraceBuilder b;
	protected DBTraceObjectManager manager;

	protected SchemaContext ctx;

	protected TraceObject root;
	protected TraceObject targetContainer;
	protected List<TraceObject> targets = new ArrayList<>();

	@Before
	public void setUpObjectManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		manager = b.trace.getObjectManager();

		ctx = XmlSchemaContext.deserialize(XML_CTX);
	}

	protected void populateModel(int targetCount) {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectKeyPath pathTargets = TraceObjectKeyPath.of("Targets");
			targetContainer = manager.createObject(pathTargets);
			root.setAttribute(Lifespan.nowOn(0), "Targets", targetContainer);
			dumpStore(manager.valueStore);

			for (int i = 0; i < targetCount; i++) {
				Lifespan lifespan = Lifespan.nowOn(i);
				TraceObject target = manager.createObject(pathTargets.index(i));
				target.setAttribute(Lifespan.ALL, "self", target);
				dumpStore(manager.valueStore);
				targetContainer.setElement(lifespan, i, target);
				dumpStore(manager.valueStore);
				targets.add(target);
				root.setAttribute(lifespan, "curTarget", target);
				dumpStore(manager.valueStore);
			}

			root.setValue(Lifespan.ALL, "anAttribute", "A primitive string");
			dumpStore(manager.valueStore);
		}
	}

	@Test
	public void testGetTrace() {
		assertEquals(b.trace, manager.getTrace());
	}

	/**
	 * Fails because you cannot use the object manager until the schema is specified and the root
	 * object is created.
	 */
	@Test(expected = IllegalStateException.class)
	public void testCreateObjectWithoutRootErr() {
		try (Transaction tx = b.startTransaction()) {
			manager.createObject(TraceObjectKeyPath.of("Test"));
		}
	}

	/**
	 * Fails because you cannot create the root object using createObject. Instead, you must use
	 * createRootObject, specifying the schema.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testCreateObjectAsRootErrNoSchema() {
		try (Transaction tx = b.startTransaction()) {
			manager.createObject(TraceObjectKeyPath.of());
		}
	}

	/**
	 * Fails because you cannot create a second root object, nor can you create any root object with
	 * createObject.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testCreateObjectAsRootErrRootExists() {
		try (Transaction tx = b.startTransaction()) {
			manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			manager.createObject(TraceObjectKeyPath.of());
		}
	}

	@Test
	public void testCreateRoot() {
		try (Transaction tx = b.startTransaction()) {
			manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	/**
	 * Fails because you cannot create a second root object.
	 */
	@Test(expected = IllegalStateException.class)
	public void testCreate2ndRootErr() {
		try (Transaction tx = b.startTransaction()) {
			manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	@Test
	public void testGetRoot() {
		assertNull(manager.getRootObject());
		assertNull(manager.getRootSchema());
		TraceObjectValue value;
		try (Transaction tx = b.startTransaction()) {
			value = manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
		assertEquals(value.getValue(), manager.getRootObject());
		assertNotNull(manager.getRootSchema());
	}

	@Test
	public void testCreateObject() {
		TraceObject obj;
		try (Transaction tx = b.startTransaction()) {
			manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			obj = manager.createObject(TraceObjectKeyPath.of("Targets"));
		}
		assertEquals(TraceObjectKeyPath.of("Targets"), obj.getCanonicalPath());
	}

	@Test
	public void testGetObjectsByCanonicalPath() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			targetContainer = manager.createObject(TraceObjectKeyPath.of("Targets"));
		}

		assertNull(manager.getObjectByCanonicalPath(TraceObjectKeyPath.of("Nothing")));
		assertEquals(root, manager.getObjectByCanonicalPath(TraceObjectKeyPath.of()));
		assertEquals(targetContainer,
			manager.getObjectByCanonicalPath(TraceObjectKeyPath.of("Targets")));
	}

	@Test
	public void testGetValuesByPathRootOnly() {
		assertEquals(0, manager.getValuePaths(Lifespan.ALL, PathPredicates.pattern()).count());

		try (Transaction tx = b.startTransaction()) {
			manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
		assertEquals(1, manager.getValuePaths(Lifespan.ALL, PathPredicates.pattern()).count());
	}

	@Test
	public void testGetObjectsByPath() {
		populateModel(2);

		assertEquals(1,
			manager.getObjectsByPath(Lifespan.at(0), TraceObjectKeyPath.parse("Targets[0]"))
					.count());
		assertEquals(0,
			manager.getObjectsByPath(Lifespan.at(0), TraceObjectKeyPath.parse("Targets[1]"))
					.count());
		assertEquals(1,
			manager.getObjectsByPath(Lifespan.at(1), TraceObjectKeyPath.parse("Targets[1]"))
					.count());
		assertEquals(2,
			manager.getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse("curTarget")).count());

		TraceObject target1 =
			manager.getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse("Targets[1]"))
					.findAny()
					.get();
		assertEquals(target1,
			manager.getObjectsByPath(Lifespan.at(1), TraceObjectKeyPath.parse("curTarget"))
					.findAny()
					.get());
	}

	@Test
	public void testGetRangeValues() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			targetContainer = manager.createObject(TraceObjectKeyPath.parse("Targets"));
			root.setAttribute(Lifespan.ALL, "Targets", targetContainer);

			TraceObjectValue rangeVal =
				root.setValue(Lifespan.nowOn(0), "a", b.range(0x1000, 0x1fff));

			assertTrue(root.getValues().contains(rangeVal));
			assertFalse(targetContainer.getValues().contains(rangeVal));
			assertEquals(rangeVal, root.getValue(0, "a"));
			assertNull(root.getValue(0, "b"));

			assertEquals(Set.of(rangeVal),
				root.getSuccessors(Lifespan.ALL, PathPredicates.parse("a"))
						.map(p -> p.getLastEntry())
						.collect(Collectors.toSet()));
			assertEquals(Set.of(),
				root.getSuccessors(Lifespan.toNow(-1), PathPredicates.parse("a"))
						.map(p -> p.getLastEntry())
						.collect(Collectors.toSet()));
			assertEquals(Set.of(),
				root.getSuccessors(Lifespan.ALL, PathPredicates.parse("b"))
						.map(p -> p.getLastEntry())
						.collect(Collectors.toSet()));
			assertEquals(Set.of(),
				targetContainer.getSuccessors(Lifespan.ALL, PathPredicates.parse("a"))
						.map(p -> p.getLastEntry())
						.collect(Collectors.toSet()));

			assertEquals(Set.of(rangeVal),
				Set.copyOf(manager.getValuesIntersecting(Lifespan.ALL, b.range(0, -1))));
			assertEquals(Set.of(),
				Set.copyOf(manager.getValuesIntersecting(Lifespan.toNow(-1), b.range(0, -1))));
			assertEquals(Set.of(),
				Set.copyOf(manager.getValuesIntersecting(Lifespan.ALL, b.range(0, 0xfff))));
		}
	}

	@Test
	public void testQueryAllInterface() {
		populateModel(3);
		TraceObject thread;
		try (Transaction tx = b.startTransaction()) {
			thread = manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}

		assertEquals(Set.of(),
			manager.queryAllInterface(Lifespan.toNow(-1), TraceObjectThread.class)
					.collect(Collectors.toSet()));
		assertEquals(Set.of(thread.queryInterface(TraceObjectThread.class)),
			manager.queryAllInterface(Lifespan.ALL, TraceObjectThread.class)
					.collect(Collectors.toSet()));
	}

	@Test
	public void testClear() {
		populateModel(3);
		assertEquals(5, manager.getAllObjects().size());

		try (Transaction tx = b.startTransaction()) {
			manager.clear();
		}
		assertEquals(0, manager.getAllObjects().size());

		populateModel(3);
		assertEquals(5, manager.getAllObjects().size());
	}

	@Test
	public void testUndoRedo() throws Exception {
		populateModel(3);
		assertEquals(5, manager.getAllObjects().size());

		b.trace.undo();
		assertEquals(0, manager.getAllObjects().size());

		b.trace.redo();
		assertEquals(5, manager.getAllObjects().size());
	}

	@Test
	public void testAbort() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			populateModel(3);
			assertEquals(5, manager.getAllObjects().size());

			tx.abort();
		}

		assertEquals(0, manager.getAllObjects().size());

		populateModel(3);
		assertEquals(5, manager.getAllObjects().size());
	}

	@Test
	public void testObjectGetTrace() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
		}
		assertEquals(b.trace, root.getTrace());
	}

	@Test
	public void testIsRoot() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			targetContainer = manager.createObject(TraceObjectKeyPath.of("Targets"));
		}

		assertTrue(root.isRoot());
		assertFalse(targetContainer.isRoot());
	}

	@Test
	public void testGetAllPaths() {
		populateModel(3);

		TraceObject object = Unique.assertOne(
			manager.getObjectsByPath(Lifespan.at(0), TraceObjectKeyPath.parse("curTarget")));

		List<TraceObjectValPath> paths =
			object.getAllPaths(Lifespan.at(0)).collect(Collectors.toList());
		assertEquals(4, paths.size());

		paths.sort(Comparator.naturalOrder());
		TraceObjectValPath path;

		path = paths.get(0);
		assertEquals(object, path.getDestination(root));
		assertEquals(PathUtils.parse("Targets[0]"), path.getKeyList());

		path = paths.get(1);
		assertEquals(object, path.getDestination(root));
		assertEquals(PathUtils.parse("Targets[0].self"), path.getKeyList());

		path = paths.get(2);
		assertEquals(object, path.getDestination(root));
		assertEquals(List.of("curTarget"), path.getKeyList());

		path = paths.get(3);
		assertEquals(object, path.getDestination(root));
		assertEquals(PathUtils.parse("curTarget.self"), path.getKeyList());

		paths = root.getAllPaths(Lifespan.ALL).collect(Collectors.toList());
		assertEquals(1, paths.size());
		path = paths.get(0);
		assertEquals(root, path.getDestination(root));
	}

	@Test
	public void testGetInterfaces() {
		TraceObject thread;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			thread = manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}
		assertEquals(Set.of(), root.getInterfaces());
		assertEquals(Set.of(TraceObjectThread.class), thread.getInterfaces());
	}

	@Test
	public void testQueryInterface() {
		TraceObject thread;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			thread = manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}
		assertNull(root.queryInterface(TraceObjectThread.class));
		TraceObjectThread threadIf = thread.queryInterface(TraceObjectThread.class);
		assertNotNull(threadIf);
		assertSame(threadIf, thread.queryInterface(TraceObjectThread.class));
	}

	@Test
	public void testGetParents() {
		populateModel(3);

		assertEquals(1, root.getParents().size());
		assertEquals(root, Unique.assertOne(targetContainer.getParents()).getParent());
		assertEquals(3, targets.get(0).getParents().size()); // curTarget, targetContainer, self
	}

	@Test
	public void testGetValues() {
		populateModel(3);

		assertEquals(3, targetContainer.getValues().size());
	}

	@Test
	public void testGetElements() {
		populateModel(3);

		assertEquals(0, root.getElements().size());
		assertEquals(3, targetContainer.getElements().size());
	}

	@Test
	public void testGetAttributes() {
		populateModel(3);

		assertEquals(5, root.getAttributes().size()); // Targets, curTarget(x3), string
		assertEquals(0, targetContainer.getAttributes().size());
	}

	@Test
	public void testGetValue() {
		populateModel(3);

		assertEquals(targetContainer, root.getValue(0, "Targets").getChild());
		assertEquals(targets.get(0), targetContainer.getValue(0, "[0]").getChild());
	}

	@Test
	public void testGetElement() {
		populateModel(3);

		assertEquals(targets.get(0), targetContainer.getElement(0, 0).getChild());
	}

	@Test
	public void testGetAttribute() {
		populateModel(3);

		assertEquals(targets.get(0), root.getAttribute(0, "curTarget").getChild());
		assertEquals(targets.get(1), root.getAttribute(1, "curTarget").getChild());
		assertEquals(targets.get(2), root.getAttribute(2, "curTarget").getChild());

		try {
			targetContainer.getAttribute(0, "[0]");
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
	}

	@Test
	public void testGetSuccessors() {
		populateModel(3);

		assertEquals(1, root.getSuccessors(Lifespan.ALL, PathPredicates.parse("")).count());

		assertEquals(1, root.getSuccessors(Lifespan.ALL, PathPredicates.parse("Targets")).count());

		assertEquals(1,
			root.getSuccessors(Lifespan.at(0), PathPredicates.parse("Targets[]")).count());
		assertEquals(1,
			targetContainer.getSuccessors(Lifespan.at(0), PathPredicates.parse("[]")).count());
		assertEquals(3,
			targetContainer.getSuccessors(Lifespan.ALL, PathPredicates.parse("[]")).count());

		assertEquals(3,
			root.getSuccessors(Lifespan.ALL, PathPredicates.parse("curTarget")).count());
		assertEquals(2,
			root.getSuccessors(Lifespan.span(0, 1), PathPredicates.parse("curTarget")).count());
		assertEquals(1,
			root.getSuccessors(Lifespan.at(1), PathPredicates.parse("curTarget")).count());
		assertEquals(0,
			root.getSuccessors(Lifespan.toNow(-1), PathPredicates.parse("curTarget")).count());

		assertEquals(1,
			root.getSuccessors(Lifespan.ALL, PathPredicates.parse("anAttribute")).count());
		assertEquals(0,
			root.getSuccessors(Lifespan.ALL, PathPredicates.parse("anAttribute.nope")).count());
	}

	@Test
	public void testGetOrderedSuccessors() {
		populateModel(3);

		assertEquals(List.of(root),
			root.getOrderedSuccessors(Lifespan.ALL, TraceObjectKeyPath.parse(""), true)
					.map(p -> p.getDestination(root))
					.collect(Collectors.toList()));
		assertEquals(List.of(root),
			root.getOrderedSuccessors(Lifespan.ALL, TraceObjectKeyPath.parse(""), false)
					.map(p -> p.getDestination(root))
					.collect(Collectors.toList()));

		assertEquals(List.of(targets.get(0), targets.get(1), targets.get(2)),
			root.getOrderedSuccessors(Lifespan.ALL, TraceObjectKeyPath.parse("curTarget"), true)
					.map(p -> p.getDestination(root))
					.collect(Collectors.toList()));
		assertEquals(List.of(targets.get(2), targets.get(1), targets.get(0)),
			root.getOrderedSuccessors(Lifespan.ALL, TraceObjectKeyPath.parse("curTarget"), false)
					.map(p -> p.getDestination(root))
					.collect(Collectors.toList()));
	}

	@Test
	public void testSetValue_TruncatesOrDeletes() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.ALL, "a", 1);
			TraceObjectValue valB = root.setValue(Lifespan.at(0), "b", 2);

			assertEquals(Lifespan.ALL, valA.getLifespan());
			assertEquals("a", valA.getEntryKey());
			assertEquals(1, valA.getValue());

			assertEquals(Lifespan.at(0), valB.getLifespan());
			assertEquals("b", valB.getEntryKey());
			assertEquals(2, valB.getValue());

			TraceObjectValue valA2 = root.setValue(Lifespan.span(0, 10), "a", 2);
			assertEquals(Lifespan.span(0, 10), valA2.getLifespan());

			assertEquals(Lifespan.toNow(-1), valA.getLifespan());
			assertFalse(valB.isDeleted());
			assertEquals(Lifespan.at(0), valB.getLifespan());

			TraceObjectValue valA3 = root.getValue(11, "a");
			assertNotNull(valA3);
			assertEquals(Lifespan.nowOn(11), valA3.getLifespan());
			assertEquals("a", valA3.getEntryKey());
			assertEquals(1, valA3.getValue());

			TraceObjectValue valA4 = root.setValue(Lifespan.span(5, 15), "a", 4);
			assertEquals(Lifespan.toNow(-1), valA.getLifespan());
			assertEquals(Lifespan.span(0, 4), valA2.getLifespan());
			assertEquals(Lifespan.span(5, 15), valA4.getLifespan());

			TraceObjectValue valA5 = root.getValue(16, "a");
			assertEquals(Lifespan.nowOn(16), valA5.getLifespan());

			root.setValue(Lifespan.ALL, "a", "Clobber");
			assertTrue(valA.isDeleted());
			assertTrue(valA2.isDeleted());
			assertTrue(valA3.isDeleted());
			assertTrue(valA4.isDeleted());
			assertTrue(valA5.isDeleted());
		}
	}

	@Test
	public void testSetValue_AbutLeftCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(-10, -1), "a", 1));
			assertEquals(Lifespan.span(-10, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetRangeValue_AbutLeftCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA =
				root.setValue(Lifespan.span(0, 9), "a", b.range(0x1000, 0x1fff));

			assertEquals(valA,
				root.setValue(Lifespan.span(-10, -1), "a", b.range(0x1000, 0x1fff)));
			assertEquals(Lifespan.span(-10, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_AbutRightCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(10, 19), "a", 1));
			assertEquals(Lifespan.span(0, 19), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_IntersectLeftCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(-5, 4), "a", 1));
			assertEquals(Lifespan.span(-5, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_IntersectRightCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(5, 14), "a", 1));
			assertEquals(Lifespan.span(0, 14), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_EqualSpansCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(0, 9), "a", 1));
			assertEquals(Lifespan.span(0, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_ContainsCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.at(5), "a", 1));
			assertEquals(Lifespan.span(0, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());

			assertEquals(valA, root.setValue(Lifespan.span(-5, 14), "a", 1));
			assertEquals(Lifespan.span(-5, 14), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_SameLeftCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(0, 5), "a", 1));
			assertEquals(Lifespan.span(0, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());

			assertEquals(valA, root.setValue(Lifespan.span(0, 14), "a", 1));
			assertEquals(Lifespan.span(0, 14), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_SameRightCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);

			assertEquals(valA, root.setValue(Lifespan.span(5, 9), "a", 1));
			assertEquals(Lifespan.span(0, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());

			assertEquals(valA, root.setValue(Lifespan.span(-5, 9), "a", 1));
			assertEquals(Lifespan.span(-5, 9), valA.getLifespan());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValue_ConnectDisjointCoalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);
			TraceObjectValue valB = root.setValue(Lifespan.span(20, 29), "a", 1);
			assertNotSame(valA, valB);
			assertEquals(2, root.getValues().size());

			assertEquals(valA, root.setValue(Lifespan.span(10, 19), "a", 1));
			assertEquals(Lifespan.span(0, 29), valA.getLifespan());
			assertTrue(valB.isDeleted());
			assertEquals(1, root.getValues().size());
		}
	}

	@Test
	public void testSetValuePrimitives() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			root.setValue(Lifespan.ALL, "aBool", true);
			root.setValue(Lifespan.ALL, "aByte", (byte) 2);
			root.setValue(Lifespan.ALL, "aChar", 'c');
			root.setValue(Lifespan.ALL, "aShort", (short) 4);
			root.setValue(Lifespan.ALL, "anInt", 5);
			root.setValue(Lifespan.ALL, "aLong", 6L);
			root.setValue(Lifespan.ALL, "aString", "Hello, 7");
			root.setValue(Lifespan.ALL, "aRange", b.range(0x1000, 0x1fff));
			root.setValue(Lifespan.ALL, "anAddress", b.addr(0x2000));

			root.setValue(Lifespan.ALL, "anEmptyIntArr", new int[] {});
			root.setValue(Lifespan.ALL, "aBoolArr", new boolean[] { false, true });
			root.setValue(Lifespan.ALL, "aByteArr", new byte[] { 2, 3, 4 });
			root.setValue(Lifespan.ALL, "aCharArr", new char[] { 'e', 'f', 'g', 'h' });
			root.setValue(Lifespan.ALL, "aShortArr", new short[] { 9, 10, 11, 12, 13 });
			root.setValue(Lifespan.ALL, "anIntArr", new int[] { 14, 15, 16, 17 });
			root.setValue(Lifespan.ALL, "aLongArr", new long[] { 18, 19 });
			root.setValue(Lifespan.ALL, "aStringArr", new String[] { "Hello,", "20" });
		}

		assertEquals(true, root.getValue(0, "aBool").getValue());
		assertEquals((byte) 2, root.getValue(0, "aByte").getValue());
		assertEquals('c', root.getValue(0, "aChar").getValue());
		assertEquals((short) 4, root.getValue(0, "aShort").getValue());
		assertEquals(5, root.getValue(0, "anInt").getValue());
		assertEquals(6L, root.getValue(0, "aLong").getValue());
		assertEquals("Hello, 7", root.getValue(0, "aString").getValue());
		assertEquals(b.range(0x1000, 0x1fff), root.getValue(0, "aRange").getValue());
		assertEquals(b.addr(0x2000), root.getValue(0, "anAddress").getValue());

		assertArrayEquals(new int[] {}, (int[]) root.getValue(0, "anEmptyIntArr").getValue());
		assertArrayEquals(new boolean[] { false, true },
			(boolean[]) root.getValue(0, "aBoolArr").getValue());
		assertArrayEquals(new byte[] { 2, 3, 4 }, (byte[]) root.getValue(0, "aByteArr").getValue());
		assertArrayEquals(new char[] { 'e', 'f', 'g', 'h' },
			(char[]) root.getValue(0, "aCharArr").getValue());
		assertArrayEquals(new short[] { 9, 10, 11, 12, 13 },
			(short[]) root.getValue(0, "aShortArr").getValue());
		assertArrayEquals(new int[] { 14, 15, 16, 17 },
			(int[]) root.getValue(0, "anIntArr").getValue());
		assertArrayEquals(new long[] { 18, 19 }, (long[]) root.getValue(0, "aLongArr").getValue());
		assertArrayEquals(new String[] { "Hello,", "20" },
			(String[]) root.getValue(0, "aStringArr").getValue());

		File saved = b.save();

		try (ToyDBTraceBuilder loaded = new ToyDBTraceBuilder(saved)) {
			TraceObject root2 = loaded.trace.getObjectManager().getRootObject();

			assertEquals(true, root2.getValue(0, "aBool").getValue());
			assertEquals((byte) 2, root2.getValue(0, "aByte").getValue());
			assertEquals('c', root2.getValue(0, "aChar").getValue());
			assertEquals((short) 4, root2.getValue(0, "aShort").getValue());
			assertEquals(5, root2.getValue(0, "anInt").getValue());
			assertEquals(6L, root2.getValue(0, "aLong").getValue());
			assertEquals("Hello, 7", root2.getValue(0, "aString").getValue());

			assertArrayEquals(new int[] {}, (int[]) root2.getValue(0, "anEmptyIntArr").getValue());
			assertArrayEquals(new boolean[] { false, true },
				(boolean[]) root2.getValue(0, "aBoolArr").getValue());
			assertArrayEquals(new byte[] { 2, 3, 4 },
				(byte[]) root2.getValue(0, "aByteArr").getValue());
			assertArrayEquals(new char[] { 'e', 'f', 'g', 'h' },
				(char[]) root2.getValue(0, "aCharArr").getValue());
			assertArrayEquals(new short[] { 9, 10, 11, 12, 13 },
				(short[]) root2.getValue(0, "aShortArr").getValue());
			assertArrayEquals(new int[] { 14, 15, 16, 17 },
				(int[]) root2.getValue(0, "anIntArr").getValue());
			assertArrayEquals(new long[] { 18, 19 },
				(long[]) root2.getValue(0, "aLongArr").getValue());
			assertArrayEquals(new String[] { "Hello,", "20" },
				(String[]) root2.getValue(0, "aStringArr").getValue());
		}
	}

	@Test
	public void testSetValue_NullContainedTruncates() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			assertNull(root.setValue(Lifespan.span(0, 9), "a", null));
			assertEquals(0, root.getValues().size());

			assertNotNull(root.setValue(Lifespan.span(0, 9), "a", 1));
			assertEquals(1, root.getValues().size());

			assertNull(root.setValue(Lifespan.at(5), "a", null));
			assertEquals(2, root.getValues().size());

			assertEquals(List.of(Lifespan.span(0, 4), Lifespan.span(6, 9)),
				root.getOrderedValues(Lifespan.ALL, "a", true)
						.map(v -> v.getLifespan())
						.collect(Collectors.toList()));
		}
	}

	@Test
	public void testSetValue_NullSameDeletes() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			assertNotNull(root.setValue(Lifespan.span(0, 9), "a", 1));
			assertEquals(1, root.getValues().size());

			assertNull(root.setValue(Lifespan.span(0, 9), "a", null));
			assertEquals(0, root.getValues().size());
		}
	}

	@Test
	public void testSetAttribute() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			root.setAttribute(Lifespan.ALL, "myAttribute", 1234);

			try {
				root.setAttribute(Lifespan.ALL, "[0]", 1234);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}
		}

		assertEquals(1234, root.getAttribute(0, "myAttribute").getValue());
		assertNull(root.getValue(0, "[0]"));
	}

	@Test
	public void testObjectDelete() throws Exception {
		populateModel(3);

		// Delete a leaf
		TraceObject t1 = targets.get(1);
		assertFalse(t1.isDeleted());
		assertEquals(3, targetContainer.getValues().size());
		assertEquals(t1, Unique.assertOne(
			manager.getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse("Targets[1]"))));
		assertEquals(t1, t1.getAttribute(1, "self").getValue());
		assertEquals(t1, root.getValue(1, "curTarget").getValue());

		try (Transaction tx = b.startTransaction()) {
			t1.delete();
		}

		assertTrue(t1.isDeleted());
		assertTrue(t1.getParents().isEmpty());
		assertEquals(2, targetContainer.getValues().size());
		assertEquals(0,
			manager.getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse("Targets[1]")).count());
		assertNull(t1.getAttribute(2, "self"));
		assertNull(root.getValue(1, "curTarget"));

		// Delete a branch (leaves stay, but detached)
		TraceObject t0 = targets.get(0);
		assertEquals(2,
			manager.getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse("Targets[]")).count());
		assertTrue(t0.getParents().stream().anyMatch(v -> v.getParent() == targetContainer));
		assertEquals(2, targetContainer.getValues().size());

		b.trace.undo();
		b.trace.redo();

		assertEquals(2, targetContainer.getValues().size());

		try (Transaction tx = b.startTransaction()) {
			targetContainer.delete();
		}

		assertEquals(0,
			manager.getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse("Targets[]")).count());
		assertFalse(t0.isDeleted());
		assertFalse(t0.getParents().stream().anyMatch(v -> v.getParent() == targetContainer));
		// A little odd, but allows branch to be replaced and successors restored later
		assertEquals(t0, root.getValue(0, "curTarget").getValue());
	}

	@Test
	public void testValueSetLifespanTruncatesOrDeletes() {
		try (Transaction tx = b.startTransaction()) {
			TraceObjectValue rootVal =
				manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			root = rootVal.getChild();

			try {
				rootVal.setLifespan(Lifespan.at(0));
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}
			assertEquals(Lifespan.ALL, rootVal.getLifespan());

			TraceObjectValue val1234 = root.setValue(Lifespan.ALL, "myValue", 1234);
			TraceObjectValue val2345 = root.setValue(Lifespan.nowOn(10), "myValue", 2345);

			assertEquals(Lifespan.toNow(9), val1234.getLifespan());

			val1234.setMaxSnap(19);
			assertEquals(19, val1234.getMaxSnap());
			assertEquals(Lifespan.toNow(19), val1234.getLifespan());
			assertEquals(Lifespan.nowOn(20), val2345.getLifespan());

			val2345.setMinSnap(10);
			assertEquals(10, val2345.getMinSnap());
			assertEquals(Lifespan.nowOn(10), val2345.getLifespan());
			assertEquals(Lifespan.toNow(9), val1234.getLifespan());

			val1234.setLifespan(Lifespan.span(20, 30));
			assertEquals(Lifespan.span(20, 30), val1234.getLifespan());
			assertEquals(Lifespan.span(10, 19), val2345.getLifespan());
			assertEquals(Lifespan.nowOn(31), root.getValue(31, "myValue").getLifespan());

			val1234.setLifespan(Lifespan.ALL);
			assertEquals(Lifespan.ALL, val1234.getLifespan());
			assertTrue(val2345.isDeleted());
		}
	}

	protected <T extends DBAnnotatedObject> void dumpStore(DBCachedObjectStore<T> store) {
		/*System.err.println("Contents of " + store);
		for (T t : store.asMap().values()) {
			System.err.println(
				"   " + t.getClass().getSimpleName() + "(key=" + t.getKey() + ",obj=" + t + ")");
		}*/
	}

	@Test
	public void testValueSetLifespan_Coalesces() {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObjectValue valA = root.setValue(Lifespan.span(0, 9), "a", 1);
			TraceObjectValue valB = root.setValue(Lifespan.span(20, 29), "a", 1);
			assertNotSame(valA, valB);

			valA.setLifespan(Lifespan.span(5, 20));
			assertEquals(Lifespan.span(5, 29), valA.getLifespan());
			assertTrue(valB.isDeleted());
		}
	}

	@Test
	public void testIsCanonical() {
		try (Transaction tx = b.startTransaction()) {
			TraceObjectValue rootVal =
				manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			root = rootVal.getChild();

			assertTrue(rootVal.isCanonical());

			TraceObjectValue primVal = root.setValue(Lifespan.ALL, "primitive", "A string");
			assertFalse(primVal.isCanonical());

			TraceObject child = manager.createObject(TraceObjectKeyPath.parse("child"));

			TraceObjectValue objVal = root.setValue(Lifespan.ALL, "child", child);
			assertTrue(objVal.isCanonical());

			TraceObjectValue linkVal = root.setValue(Lifespan.ALL, "link", child);
			assertFalse(linkVal.isCanonical());
		}
	}

	@Test
	public void testValueDelete() {
		try (Transaction tx = b.startTransaction()) {
			TraceObjectValue rootVal =
				manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			root = rootVal.getChild();

			try {
				rootVal.delete();
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}

			TraceObjectValue val = root.setValue(Lifespan.ALL, "myValue", 1234);
			assertFalse(val.isDeleted());
			assertEquals(val, root.getValue(0, "myValue"));

			val.delete();
			assertTrue(val.isDeleted());
			assertNull(root.getValue(0, "myValue"));
		}
	}

	@Test
	public void testValueTruncateOrDelete() {
		try (Transaction tx = b.startTransaction()) {
			TraceObjectValue rootVal =
				manager.createRootObject(ctx.getSchema(new SchemaName("Session")));
			root = rootVal.getChild();

			try {
				rootVal.truncateOrDelete(Lifespan.nowOn(0));
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}

			TraceObjectValue stringVal = root.setValue(Lifespan.ALL, "myValue", "A string");

			assertEquals(stringVal, stringVal.truncateOrDelete(Lifespan.nowOn(11)));
			assertEquals(Lifespan.toNow(10), stringVal.getLifespan());

			TraceObjectValue split = stringVal.truncateOrDelete(Lifespan.at(0));
			assertNotSame(stringVal, split);
			assertEquals(Lifespan.toNow(-1), stringVal.getLifespan());
			assertEquals(Lifespan.span(1, 10), split.getLifespan());
			assertEquals("A string", split.getValue());

			assertNull(stringVal.truncateOrDelete(Lifespan.ALL));
			assertTrue(stringVal.isDeleted());
			assertFalse(split.isDeleted()); // Other values not affected
		}
	}
}
