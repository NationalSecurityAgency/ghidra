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
package ghidra.pcode.emu.symz3.trace;

import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Context;

import db.Transaction;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.AbstractTracePcodeEmulatorTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

public class SymZ3TracePcodeEmulatorTest extends AbstractTracePcodeEmulatorTest {

	/**
	 * Test that state is properly read from trace memory
	 * 
	 * <p>
	 * We isolate exactly a read by executing sleigh.
	 * 
	 * @throws Throwable because
	 */
	@Test
	public void testReadStateMemory() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, "", List.of());

			try (Transaction tid = tb.startTransaction()) {
				TracePropertyMap<String> symMap = tb.trace.getAddressPropertyManager()
						.getOrCreatePropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME,
							String.class);

				try (Context ctx = new Context()) {
					SymValueZ3 test = new SymValueZ3(ctx, ctx.mkBV(0, 8));
					symMap.set(Lifespan.nowOn(0), tb.range(0x00400000, 0x00400003),
						test.serialize());
				}
			}

			SymZ3TracePcodeEmulator emu = new SymZ3TracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread = emu.newThread(thread.getPath());
			emuThread.getExecutor().executeSleigh("RAX = *0x00400000:8;");

			Pair<byte[], SymValueZ3> valRAX =
				emuThread.getState().getVar(tb.language.getRegister("RAX"), Reason.INSPECT);

			Msg.info(this, valRAX);

			// TODO: assertion needed
		}
	}

	@Test
	public void testReadStateRegister() throws Throwable {
		Msg.info(this, "");
		Msg.info(this, "BEGIN testReadStateRegister");
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, "", List.of());
			Register regRAX = tb.language.getRegister("RAX");
			Register regEAX = tb.language.getRegister("EAX");
			Register regRBX = tb.language.getRegister("RBX");

			// TODO... test on EBX

			try (Transaction tid = tb.startTransaction()) {
				TracePropertyMap<String> symZ3Map = tb.trace.getAddressPropertyManager()
						.getOrCreatePropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME,
							String.class);
				TracePropertyMapSpace<String> mapSpace =
					symZ3Map.getPropertyMapRegisterSpace(thread, 0, true);
				mapSpace.set(Lifespan.nowOn(0), regRBX, "test_0");
			}

			SymZ3TracePcodeEmulator emu = new SymZ3TracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread = emu.newThread(thread.getPath());

			try (Context ctx = new Context()) {
				BitVecExpr e = ctx.mkBVConst("symbolic_RBX", 64);
				SymValueZ3 symVal = new SymValueZ3(ctx, e);
				emuThread.getState().setVar(tb.reg("RBX"), Pair.of(tb.arr(0, 0, 0, 0), symVal));
			}

			emuThread.getExecutor().executeSleigh("RAX = RBX;");

			Msg.debug(this, "executed the line 'RAX = RBX'");
			Pair<byte[], SymValueZ3> valRAX = emuThread.getState().getVar(regRAX, Reason.INSPECT);

			Msg.info(this, "read the value of RAX:" + valRAX);

			Pair<byte[], SymValueZ3> valEAX = emuThread.getState().getVar(regEAX, Reason.INSPECT);

			Msg.info(this, "read the value of EAX:" + valEAX);

			Msg.info(this, "END testReadStateRegister");
			Msg.info(this, "");
		}
	}

	@Test
	public void testWriteStateMemory() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			initTrace(tb, "", List.of());
			SymZ3TracePcodeEmulator emu = new SymZ3TracePcodeEmulator(tb.host, 0);

			Address addr = tb.addr(0x00400000);
			try (Context ctx = new Context()) {

				BitVecExpr e = ctx.mkBVConst("symbolic_buffer", 64);
				SymValueZ3 symVal = new SymValueZ3(ctx, e);

				emu.getSharedState()
						.setVar(tb.addr(0x00400000), 8, true,
							Pair.of(tb.arr(0, 0, 0, 0, 0, 0, 0, 0), symVal));
			}

			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}
			TracePropertyMap<String> map =
				tb.trace.getAddressPropertyManager()
						.getPropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME, String.class);

			TracePropertyMapSpace<String> backing =
				map.getPropertyMapSpace(addr.getAddressSpace(), false);

			Msg.info(this, "to pass this test, we fetch from backing:" + backing +
				" with address: " + addr + " with offset: " + addr.getOffset());
			Msg.info(this, backing.get(1, addr));

		}
	}

	@Test
	public void testWriteStateRegister() throws Throwable {

		Msg.info(this, "");
		Msg.info(this, "BEGIN testWriteStateRegister");

		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {

			TraceThread thread = initTrace(tb, "", List.of());

			SymZ3TracePcodeEmulator emu = new SymZ3TracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread = emu.newThread(thread.getPath());

			try (Context ctx = new Context()) {
				BitVecExpr e = ctx.mkBVConst("symbolic_EAX", 32);
				SymValueZ3 symVal = new SymValueZ3(ctx, e);
				emuThread.getState().setVar(tb.reg("EAX"), Pair.of(tb.arr(0, 0, 0, 0), symVal));
			}

			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);

				// grab the name property from the abstract class.... 

				TracePropertyMap<String> symMap =
					tb.trace.getAddressPropertyManager()
							.getPropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME, String.class);

				Msg.info(this, "we have a symMap: " + symMap);

				TracePropertyMapSpace<String> mapSpace = symMap
						.getPropertyMapRegisterSpace(thread, 0, true);

				Msg.info(this, "we have a mapSpace: " + mapSpace);
				Msg.info(this, "entries from the map space: " +
					mapSpace.getEntries(Lifespan.at(1), tb.reg("EAX")));
			}

			Msg.info(this, "END testWriteStateRegister");
			Msg.info(this, "");

		}
	}

	@Test
	public void testSymbolicMemory() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			AddressSpace ram = tb.language.getAddressFactory().getDefaultAddressSpace();
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					""",
				List.of(
					"MOV RBX, qword ptr [0x00600000]",
					"MOV qword ptr [0x00600020], RBX",
					"MOV dword ptr [RBP + -0x18],EAX",
					"MOV qword ptr [RBP + -0x28],RAX",
					"MOV RBP, qword ptr [RBP + -0x28]"));

			SymZ3TracePcodeEmulator emu = new SymZ3TracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread = emu.newThread(thread.getPath());

			emuThread.stepInstruction();
			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}
			emuThread.stepInstruction();
			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 2, 0);
			}
			emuThread.stepInstruction();
			emuThread.stepInstruction();
			emuThread.stepInstruction();

			System.out.println("Instructions emulated:");
			emu.printInstructions(System.out);
			System.out.println("Pcode emulated:");
			emu.printOps(System.out);
			System.out.println("Summary:");
			emu.printSymbolicSummary(System.out);

			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 5, 0);
			}

			TracePropertyMap<String> symMap =
				tb.trace.getAddressPropertyManager()
						.getPropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME, String.class);

			TracePropertyMapSpace<String> backing = symMap.getPropertyMapSpace(ram, false);

			Msg.debug(this, "read: " +
				backing.getEntries(Lifespan.at(5), tb.range(0x00600020, 0x00600027)));
		}
	}

	@Test
	public void testPrecondition() throws Throwable {
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("Test", "x86:LE:64:default")) {
			TraceThread thread = initTrace(tb, """
					RIP = 0x00400000;
					""",
				List.of(
					"MOV dword ptr [RBP + -0x18],EAX",
					"MOVZX EAX, byte ptr [RBP + -0x28]"));

			SymZ3TracePcodeEmulator emu = new SymZ3TracePcodeEmulator(tb.host, 0);
			PcodeThread<Pair<byte[], SymValueZ3>> emuThread = emu.newThread(thread.getPath());

			emuThread.stepInstruction();
			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 1, 0);
			}
			emuThread.stepInstruction();
			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 2, 0);
			}

			emu.printSymbolicSummary(System.out);

			try (Transaction tid = tb.startTransaction()) {
				emu.writeDown(tb.host, 5, 0);
			}

			TracePropertyMap<String> symMap =
				tb.trace.getAddressPropertyManager()
						.getPropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME, String.class);

			AddressSpace noSpace = Address.NO_ADDRESS.getAddressSpace();
			TracePropertyMapSpace<String> backing = symMap.getPropertyMapSpace(noSpace, false);
			Msg.debug(this, "read: " +
				backing.getEntries(Lifespan.at(5), tb.range(0x00600020, 0x00600027)));
		}
	}

}
