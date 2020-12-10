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
package ghidra.dbg.jdi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.connect.Connector.Argument;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;

import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

@Ignore("These crash in Gradle")
public class JdiExperimentsTest {
	protected VirtualMachineManager vmm = Bootstrap.virtualMachineManager();

	@Test
	public void testArguments() throws Exception {
		LaunchingConnector conn = vmm.defaultConnector();
		Map<String, Argument> args = conn.defaultArguments();
		Msg.debug(this, "Args: " + args);
	}

	public static class HelloWorld {
		public static void main(String[] args) {
			System.out.println("Hello, World!");
		}
	}

	@Test
	public void testSimpleLaunch() throws Exception {
		LaunchingConnector conn = vmm.defaultConnector();
		Map<String, Argument> args = conn.defaultArguments();
		args.get("options").setValue("-cp \"" + System.getProperty("java.class.path") + "\"");
		args.get("main").setValue(HelloWorld.class.getName());
		VirtualMachine vm = conn.launch(args);

		for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof VMStartEvent);
		}

		Msg.info(this, "Version: " + vm.version());
		Msg.info(this, "Description: " + vm.description());
		Msg.info(this, "Name: " + vm.name());

		vm.resume();

		BufferedReader reader =
			new BufferedReader(new InputStreamReader(vm.process().getInputStream()));
		String hw = reader.readLine();
		assertEquals("Hello, World!", hw);

		vm.dispose();
	}

	@Test
	public void testSimpleSocketAttachJDWP() throws Exception {
		// Launch a VM so that we have an "existing process"
		ProcessBuilder pb = new ProcessBuilder("java",
			"-agentlib:jdwp=transport=dt_socket,address=0,server=y,suspend=y",
			"-cp", System.getProperty("java.class.path"),
			HelloWorld.class.getName());
		Process hwProc = pb.start();

		// The JDWP Agent will print the open port before suspending
		BufferedReader reader =
			new BufferedReader(new InputStreamReader(hwProc.getInputStream()));
		String listenLine = reader.readLine();
		Msg.info(this, listenLine);
		assertTrue(listenLine.startsWith("Listening"));
		String[] parts = listenLine.split("\\s+");
		String port = parts[parts.length - 1];
		// OK, everything above simulates existing process, now the real connection begins

		AttachingConnector tcpConn = vmm.attachingConnectors()
				.stream()
				.filter(c -> c.defaultArguments().containsKey("hostname"))
				.findFirst()
				.orElse(null);
		Map<String, Argument> args = tcpConn.defaultArguments();
		args.get("hostname").setValue("localhost");
		args.get("port").setValue(port);
		VirtualMachine vm = tcpConn.attach(args);

		for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof VMStartEvent);
		}

		vm.resume();

		String hw = reader.readLine();
		assertEquals("Hello, World!", hw);

		vm.dispose();
	}

	@Test
	public void testSimpleProcessAttachJDWP() throws Exception {
		// Launch a VM so that we have an "existing process"
		ProcessBuilder pb = new ProcessBuilder("java",
			"-agentlib:jdwp=transport=dt_socket,address=0,server=y,suspend=y",
			"-cp", System.getProperty("java.class.path"),
			HelloWorld.class.getName());
		Process hwProc = pb.start();

		// The JDWP Agent will print the open port before suspending
		BufferedReader reader =
			new BufferedReader(new InputStreamReader(hwProc.getInputStream()));
		String listenLine = reader.readLine();
		// We don't need the port, but we still use this to wait for listen
		Msg.info(this, listenLine);
		// OK, everything above simulates existing process, now the real connection begins

		AttachingConnector procConn = vmm.attachingConnectors()
				.stream()
				.filter(c -> c.defaultArguments().containsKey("pid"))
				.findFirst()
				.orElse(null);
		Map<String, Argument> args = procConn.defaultArguments();
		args.get("pid").setValue("" + hwProc.pid());
		VirtualMachine vm = procConn.attach(args);

		for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof VMStartEvent);
		}

		vm.resume();

		String hw = reader.readLine();
		assertEquals("Hello, World!", hw);

		vm.dispose();
	}

	@Test
	public void testSimpleListenAttachJDWP() throws Exception {
		ListeningConnector lConn = vmm.listeningConnectors()
				.stream()
				.filter(c -> c.defaultArguments().containsKey("localAddress"))
				.findFirst()
				.orElse(null);

		Map<String, Argument> args = lConn.defaultArguments();
		args.get("port").setValue("0");
		args.get("localAddress").setValue("localhost");
		String addr = lConn.startListening(args);

		ProcessBuilder pb = new ProcessBuilder("java",
			"-agentlib:jdwp=transport=dt_socket,address=" + addr + ",server=n,suspend=y",
			"-cp", System.getProperty("java.class.path"),
			HelloWorld.class.getName());
		Process hwProc = pb.start();

		VirtualMachine vm = lConn.accept(args);

		for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof VMStartEvent);
		}

		vm.resume();

		BufferedReader reader =
			new BufferedReader(new InputStreamReader(hwProc.getInputStream()));
		String hw = reader.readLine();
		assertEquals("Hello, World!", hw);

		vm.dispose();
	}

	@Test
	@Ignore("Enable after you've manually launched a target")
	public void testAtttachJDWP() throws Exception {
		AttachingConnector tcpConn = vmm.attachingConnectors()
				.stream()
				.filter(c -> c.defaultArguments().containsKey("hostname"))
				.findFirst()
				.orElse(null);
		Map<String, Argument> args = tcpConn.defaultArguments();
		args.get("hostname").setValue("localhost");
		args.get("port").setValue("8000");
		VirtualMachine vm = tcpConn.attach(args);

		/*for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof VMStartEvent);
		}*/

		Msg.info(this, "Version: " + vm.version());
		Msg.info(this, "Description: " + vm.description());
		Msg.info(this, "Name: " + vm.name());
	}

	@Test
	public void testWhatIsCodeIndex() throws Exception {
		LaunchingConnector conn = vmm.defaultConnector();
		Map<String, Argument> args = conn.defaultArguments();
		args.get("options").setValue("-cp \"" + System.getProperty("java.class.path") + "\"");
		args.get("main").setValue(HelloWorld.class.getName());

		VirtualMachine vm = conn.launch(args);
		for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof VMStartEvent);
		}

		Msg.debug(this, "Resuming with request");
		//MethodEntryRequest meReq = vm.eventRequestManager().createMethodEntryRequest();
		//meReq.enable();

		ClassPrepareRequest cpReq = vm.eventRequestManager().createClassPrepareRequest();
		cpReq.enable();

		vm.resume();

		untilHw: while (true) {
			for (Event evt : vm.eventQueue().remove(1000)) {
				Msg.debug(this, "Event: " + evt);
				if (evt instanceof ClassPrepareEvent) {
					ClassPrepareEvent cpEvt = (ClassPrepareEvent) evt;
					Msg.debug(this, "  Type: " + cpEvt.referenceType());
					if (cpEvt.referenceType().name().contains(HelloWorld.class.getSimpleName())) {
						break untilHw;
					}
				}
			}
			vm.resume();
		}

		cpReq.disable();

		List<ReferenceType> hwClasses = vm.classesByName(HelloWorld.class.getName());
		assertEquals(1, hwClasses.size());

		ReferenceType hwClass = hwClasses.get(0);
		List<Method> hwMainMethods = hwClass.methodsByName("main");
		assertEquals(1, hwMainMethods.size());
		Method hwMainMethod = hwMainMethods.get(0);

		Msg.debug(this, "Code: " + NumericUtilities.convertBytesToString(hwMainMethod.bytecodes()));

		BreakpointRequest bpMainReq =
			vm.eventRequestManager().createBreakpointRequest(hwMainMethod.location());
		bpMainReq.enable();

		vm.resume();

		ThreadReference thread = null;
		for (Event evt : vm.eventQueue().remove(1000)) {
			Msg.debug(this, "Event: " + evt);
			assertTrue(evt instanceof BreakpointEvent);
			BreakpointEvent bpMainEvt = (BreakpointEvent) evt;
			thread = bpMainEvt.thread();
		}
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_MIN,
					StepRequest.STEP_INTO);
		stepReq.enable();

		while (thread.frame(0).location().method() == hwMainMethod) {
			Location loc = thread.frame(0).location();
			Msg.debug(this, String.format("Mth=%s,Idx=%s", loc.method(), loc.codeIndex()));
			vm.resume();
		}
		stepReq.disable();
		vm.resume();

		BufferedReader reader =
			new BufferedReader(new InputStreamReader(vm.process().getInputStream()));
		String hw = reader.readLine();
		assertEquals("Hello, World!", hw);

	}
}
