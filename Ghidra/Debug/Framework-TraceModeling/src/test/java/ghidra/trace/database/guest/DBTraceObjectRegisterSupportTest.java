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
package ghidra.trace.database.guest;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.target.DBTraceObjectManagerTest;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectRegisterSupportTest extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceObjectManager manager;

	protected SchemaContext ctx;
	protected TraceObject root;

	@Before
	public void setUpObjectManagerTest() throws Exception {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		manager = b.trace.getObjectManager();

		ctx = XmlSchemaContext.deserialize(DBTraceObjectManagerTest.XML_CTX);
	}

	@Test
	public void testRegisterMappingHost() throws DuplicateNameException {
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regR0 = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[r0]"));
			regR0.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers",
						b.trace.getBaseAddressFactory().getRegisterSpace());

			regR0.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 64);
			regR0.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x1234);
		}

		AddressSpace overlaySpace =
			b.trace.getBaseAddressFactory().getAddressSpace("Targets[0].Threads[0].Registers");
		TraceMemorySpace regSpace = b.trace.getMemoryManager().getMemorySpace(overlaySpace, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regSpace.getValue(0, b.reg("r0")).getUnsignedValue());
	}

	@Test
	public void testRegisterMappingGuest() throws Throwable {
		TraceGuestPlatform amd64;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regRAX = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[RAX]"));
			regRAX.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers",
						b.trace.getBaseAddressFactory().getRegisterSpace());

			amd64 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getSLEIGH_X86_64_LANGUAGE().getCompilerSpecByID(new CompilerSpecID("gcc")));
			amd64.addMappedRegisterRange();

			regRAX.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 64);
			regRAX.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x1234);
		}

		AddressSpace overlaySpace =
			b.trace.getBaseAddressFactory().getAddressSpace("Targets[0].Threads[0].Registers");
		TraceMemorySpace regSpace = b.trace.getMemoryManager().getMemorySpace(overlaySpace, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regSpace.getValue(amd64, 0, amd64.getLanguage().getRegister("RAX")).getUnsignedValue());
	}

	@Test
	public void testRegisterMappingLabel() throws Throwable {
		TraceGuestPlatform amd64;
		Register RAX;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regOrigRAX = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[orig_rax]"));
			regOrigRAX.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers",
						b.trace.getBaseAddressFactory().getRegisterSpace());

			amd64 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getSLEIGH_X86_64_LANGUAGE().getCompilerSpecByID(new CompilerSpecID("gcc")));
			amd64.addMappedRegisterRange();
			RAX = amd64.getLanguage().getRegister("RAX");
			amd64.addRegisterMapOverride(RAX, "orig_rax");

			regOrigRAX.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 64);
			regOrigRAX.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x1234);
		}

		AddressSpace overlaySpace =
			b.trace.getBaseAddressFactory().getAddressSpace("Targets[0].Threads[0].Registers");
		TraceMemorySpace regSpace = b.trace.getMemoryManager().getMemorySpace(overlaySpace, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regSpace.getValue(amd64, 0, RAX).getUnsignedValue());
	}

	@Test
	public void testRegisterMappingGuestMemoryMapped() throws Throwable {
		TraceGuestPlatform avr8;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regR0 = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[R0]"));
			regR0.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			avr8 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getLanguageService().getLanguage(new LanguageID("avr8:LE:16:default"))
								.getCompilerSpecByID(new CompilerSpecID("gcc")));
			avr8.addMappedRange(b.addr(0),
				avr8.getLanguage().getDefaultDataSpace().getAddress(0), 0x1000);

			regR0.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 8);
			regR0.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x12);
		}

		assertEquals(BigInteger.valueOf(0x12), b.trace.getMemoryManager()
				.getValue(avr8, 0, avr8.getLanguage().getRegister("R0"))
				.getUnsignedValue());
		ByteBuffer buf = ByteBuffer.allocate(1);
		assertEquals(1, b.trace.getMemoryManager().getBytes(0, b.addr(0), buf));
		assertArrayEquals(b.arr(0x12), buf.array());
	}

	@Test
	public void testRegisterMappingGuestMemoryMappedHostOverlay() throws Throwable {
		TraceGuestPlatform avr8;
		AddressSpace overlay;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regR0 = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[R0]"));
			regR0.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			overlay = b.trace.getMemoryManager()
					.createOverlayAddressSpace("custom",
						b.trace.getBaseAddressFactory().getDefaultAddressSpace());

			avr8 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getLanguageService().getLanguage(new LanguageID("avr8:LE:16:default"))
								.getCompilerSpecByID(new CompilerSpecID("gcc")));
			avr8.addMappedRange(b.addr(overlay, 0),
				avr8.getLanguage().getDefaultDataSpace().getAddress(0), 0x1000);

			regR0.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 8);
			regR0.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x12);
		}

		assertEquals(BigInteger.valueOf(0x12), b.trace.getMemoryManager()
				.getValue(avr8, 0, avr8.getLanguage().getRegister("R0"))
				.getUnsignedValue());
		ByteBuffer buf = ByteBuffer.allocate(1);
		assertEquals(1, b.trace.getMemoryManager().getBytes(0, b.addr(overlay, 0), buf));
		assertArrayEquals(b.arr(0x12), buf.array());
	}

	@Test
	public void testRegisterMappingLabelMemoryMapped() throws Throwable {
		TraceGuestPlatform avr8;
		Register R0;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regR0 = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[orig_r0]"));
			regR0.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			avr8 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getLanguageService().getLanguage(new LanguageID("avr8:LE:16:default"))
								.getCompilerSpecByID(new CompilerSpecID("gcc")));
			avr8.addMappedRange(b.addr(0),
				avr8.getLanguage().getDefaultDataSpace().getAddress(0), 0x1000);
			R0 = avr8.getLanguage().getRegister("R0");
			avr8.addRegisterMapOverride(R0, "orig_r0");

			regR0.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 8);
			regR0.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x12);
		}

		assertEquals(BigInteger.valueOf(0x12),
			b.trace.getMemoryManager().getValue(avr8, 0, R0).getUnsignedValue());
		ByteBuffer buf = ByteBuffer.allocate(1);
		assertEquals(1, b.trace.getMemoryManager().getBytes(0, b.addr(0), buf));
		assertArrayEquals(b.arr(0x12), buf.array());
	}

	@Test
	public void testAddLabelCopiesRegisterValues() throws Throwable {
		TraceGuestPlatform amd64;
		Register RAX;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regOrigRAX = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[orig_rax]"));
			regOrigRAX.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers",
						b.trace.getBaseAddressFactory().getRegisterSpace());

			amd64 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getSLEIGH_X86_64_LANGUAGE().getCompilerSpecByID(new CompilerSpecID("gcc")));
			amd64.addMappedRegisterRange();

			regOrigRAX.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 64);
			regOrigRAX.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x1234);

			RAX = amd64.getLanguage().getRegister("RAX");
			amd64.addRegisterMapOverride(RAX, "orig_rax");
		}

		AddressSpace overlaySpace =
			b.trace.getBaseAddressFactory().getAddressSpace("Targets[0].Threads[0].Registers");
		TraceMemorySpace regSpace = b.trace.getMemoryManager().getMemorySpace(overlaySpace, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regSpace.getValue(amd64, 0, RAX).getUnsignedValue());
	}

	@Test
	public void testAddLabelCopiesRegisterValuesMemoryMapped() throws Throwable {
		TraceGuestPlatform avr8;
		Register R0;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regR0 = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[orig_r0]"));
			regR0.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			avr8 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getLanguageService().getLanguage(new LanguageID("avr8:LE:16:default"))
								.getCompilerSpecByID(new CompilerSpecID("gcc")));
			avr8.addMappedRange(b.addr(0),
				avr8.getLanguage().getDefaultDataSpace().getAddress(0), 0x1000);

			regR0.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 8);
			regR0.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x12);

			R0 = avr8.getLanguage().getRegister("R0");
			avr8.addRegisterMapOverride(R0, "orig_r0");
		}

		assertEquals(BigInteger.valueOf(0x12),
			b.trace.getMemoryManager().getValue(avr8, 0, R0).getUnsignedValue());
		ByteBuffer buf = ByteBuffer.allocate(1);
		assertEquals(1, b.trace.getMemoryManager().getBytes(0, b.addr(0), buf));
		assertArrayEquals(b.arr(0x12), buf.array());
	}

	@Test
	public void testAddGuestMappingCopiesRegisterValues() throws Throwable {
		TraceGuestPlatform amd64;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regRAX = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[RAX]"));
			regRAX.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers",
						b.trace.getBaseAddressFactory().getRegisterSpace());

			regRAX.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 64);
			regRAX.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x1234);

			amd64 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getSLEIGH_X86_64_LANGUAGE().getCompilerSpecByID(new CompilerSpecID("gcc")));
			amd64.addMappedRegisterRange();
		}

		AddressSpace overlaySpace =
			b.trace.getBaseAddressFactory().getAddressSpace("Targets[0].Threads[0].Registers");
		TraceMemorySpace regSpace = b.trace.getMemoryManager().getMemorySpace(overlaySpace, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regSpace.getValue(amd64, 0, amd64.getLanguage().getRegister("RAX")).getUnsignedValue());
	}

	@Test
	public void testAddOverlaySpaceCopiesRegisterValues() throws Throwable {
		TraceGuestPlatform amd64;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			TraceObject thread =
				manager.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0]"));
			thread.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			TraceObject regRAX = manager.createObject(
				TraceObjectKeyPath.parse("Targets[0].Threads[0].Registers.User[RAX]"));
			regRAX.insert(Lifespan.nowOn(0), ConflictResolution.DENY);

			regRAX.setValue(Lifespan.nowOn(0), TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME, 64);
			regRAX.setValue(Lifespan.nowOn(0), TargetRegister.VALUE_ATTRIBUTE_NAME, 0x1234);

			amd64 = b.trace.getPlatformManager()
					.addGuestPlatform(
						getSLEIGH_X86_64_LANGUAGE().getCompilerSpecByID(new CompilerSpecID("gcc")));
			amd64.addMappedRegisterRange();

			b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers",
						b.trace.getBaseAddressFactory().getRegisterSpace());
		}

		AddressSpace overlaySpace =
			b.trace.getBaseAddressFactory().getAddressSpace("Targets[0].Threads[0].Registers");
		TraceMemorySpace regSpace = b.trace.getMemoryManager().getMemorySpace(overlaySpace, false);
		assertEquals(BigInteger.valueOf(0x1234),
			regSpace.getValue(amd64, 0, amd64.getLanguage().getRegister("RAX")).getUnsignedValue());
	}

	@Test
	public void testPlatformGetConventionalRegisterRange() throws Throwable {
		DBTraceGuestPlatform x86;
		AddressSpace registers = b.trace.getBaseAddressFactory().getRegisterSpace();
		AddressSpace overlay;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			x86 = b.trace.getPlatformManager()
					.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			x86.addMappedRegisterRange();

			overlay = b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers", registers);
		}
		Register EAX = x86.getLanguage().getRegister("EAX");

		// TODO: These hardcoded offsets could be fragile
		assertEquals(b.range(registers, 0x1104, 0x1107),
			x86.getConventionalRegisterRange(registers, EAX));
		assertEquals(b.range(overlay, 0x1104, 0x1107),
			x86.getConventionalRegisterRange(overlay, EAX));
	}

	protected static void assertMatches(String path, PathMatcher matcher) {
		String message = matcher + " does not match " + path;
		assertTrue(message, matcher.matches(PathUtils.parse(path)));
	}

	@Test
	public void testPlatformGetConventionalRegisterPath() throws Throwable {
		DBTraceGuestPlatform x86;
		AddressSpace registers = b.trace.getBaseAddressFactory().getRegisterSpace();
		AddressSpace overlay;
		Register EAX;
		Register EBX;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();

			x86 = b.trace.getPlatformManager()
					.addGuestPlatform(b.getCompiler("x86:LE:32:default", "gcc"));
			x86.addMappedRegisterRange();
			EAX = x86.getLanguage().getRegister("EAX");
			EBX = x86.getLanguage().getRegister("EBX");

			x86.addRegisterMapOverride(EAX, "orig_eax");

			overlay = b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers", registers);
		}

		assertMatches("Targets[0].Threads[0].Registers.User[EBX]",
			x86.getConventionalRegisterPath(overlay, EBX));
		assertMatches("Targets[0].Threads[0].Registers.User[orig_eax]",
			x86.getConventionalRegisterPath(overlay, EAX));
		assertMatches("Targets[0].Threads[0].Registers.User[r0]",
			b.host.getConventionalRegisterPath(overlay, b.reg("r0")));
	}

	@Test
	public void testPlatformGetConventionalRegisterPathAlias() throws Throwable {
		AddressSpace registers = b.trace.getBaseAddressFactory().getRegisterSpace();
		AddressSpace overlay;
		Register r0;
		try (Transaction tx = b.startTransaction()) {
			root = manager.createRootObject(ctx.getSchema(new SchemaName("Session"))).getChild();
			r0 = b.language.getRegister("r0");
			overlay = b.trace.getMemoryManager()
					.createOverlayAddressSpace("Targets[0].Threads[0].Registers", registers);
		}

		PathMatcher matcher = b.host.getConventionalRegisterPath(overlay, r0);
		assertMatches("Targets[0].Threads[0].Registers.User[r0]", matcher);
		assertMatches("Targets[0].Threads[0].Registers.User[a0]", matcher);
		assertMatches("Targets[0].Threads[0].Registers.User[R0]", matcher);
		assertMatches("Targets[0].Threads[0].Registers.User[A0]", matcher);
	}
}
