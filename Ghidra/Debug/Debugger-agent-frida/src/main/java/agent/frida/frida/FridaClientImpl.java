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
package agent.frida.frida;

import java.math.BigInteger;
import java.util.*;

import agent.frida.manager.*;
import ghidra.util.Msg;

public class FridaClientImpl implements FridaClient {

	private FridaManager manager;
	private FridaDebugger d;
	private FridaTarget initialTarget;
	private List<FridaTarget> targets;

	public FridaClientImpl() {
	}

	@Override
	public FridaClient createClient() {
		d = FridaEng.init();
		targets = new ArrayList<>();
		initialTarget = FridaEng.createTarget(d);
		targets.add(initialTarget);
		//cmd = sbd.GetCommandInterpreter();
		return this;
	}

	public FridaDebugger getDebugger() {
		return d;
	}

	@Override
	public FridaServerId getLocalServer() {
		return new FridaServerId(0);
	}

	@Override
	public FridaSession attachProcess(FridaServerId si, int keyType, String key, boolean wait,
			boolean async) {
		FridaError error = new FridaError();
		FridaTarget target = createNullSession();
		targets.add(target);
		
		int radix = 10;
		if (key.startsWith("0x")) {
			key = key.substring(2);
			radix = 16;
		}
		BigInteger processId = new BigInteger(key, radix);
		FridaSession session = target.attach(processId, error);
		if (!error.success()) {
			Msg.error(this, "Error while attaching to " + key);
			Msg.error(this, error.getDescription());
			return null;
		}
			
		manager.updateState(session);
		target.setSession(session);
		return session;
	}

	@Override
	public FridaSession createProcess(FridaServerId si, String fileName) {
		return createProcess(si, fileName, new ArrayList<String>(), new ArrayList<String>(), "");
	}

	@Override
	public FridaSession createProcess(FridaServerId si, String fileName,
			List<String> args, List<String> envp, String workingDir) {
		FridaError error = new FridaError();
		
		String[] argArr = args.toArray(new String[args.size()]);
		String[] envArr = envp.isEmpty() ? null : envp.toArray(new String[envp.size()]);
		FridaSession session = manager.getCurrentTarget().launchSimple(argArr, envArr, workingDir);
		if (!error.success()) {
			Msg.error(this, "Error for create process");
			Msg.error(this, error.getDescription());
			return null;
		}
		manager.updateState(session);
		return session;
	}

	@Override
	public FridaSession createProcess(FridaServerId si, String fileName,
			List<String> args, List<String> envp, List<String> pathsIO,
			String workingDir, long createFlags, boolean stopAtEntry) {
		FridaTarget target = manager.getCurrentTarget();

		String[] argArr = args.toArray(new String[args.size()]);
		// null for envp means use the default environment
		String[] envArr = envp.isEmpty() ? null : envp.toArray(new String[envp.size()]);
		String pathSTDIN = pathsIO.get(0);
		String pathSTDOUT = pathsIO.get(1);
		String pathSTDERR = pathsIO.get(2);
		FridaError error = new FridaError();
		FridaSession session = target.launch(fileName, argArr, envArr,
			pathSTDIN, pathSTDOUT, pathSTDERR, workingDir, createFlags, stopAtEntry, error);
		//FridaProcess process = session.Launch(listener, null, null, "", "", "", "", 0, true, error);
		if (!error.success()) {
			Msg.error(this, "Error while launching " + fileName);
			Msg.error(this, error.getDescription());
			return null;
		}
			
		manager.updateState(session);
		return session;
	}

	@Override
	public void terminateCurrentProcess(FridaTarget target) {
		FridaProcess process = target.getProcess();
		if (process != null) {
			FridaError error = process.kill();
			if (!error.success()) {
				Msg.error(this, error.getDescription());
			}
		}
	}

	@Override
	public void destroyCurrentProcess(FridaTarget target) {
		FridaProcess process = target.getProcess();
		FridaError error = process.destroy();
		if (!error.success()) {
			Msg.error(this, error.getDescription());
		}
	}

	@Override
	public void detachCurrentProcess(FridaTarget target) {
		FridaProcess process = target.getProcess();
		FridaError error = process.destroy();
		if (!error.success()) {
			Msg.error(this, error.getDescription());
		}
	}

	public FridaTarget createNullSession() {
		return FridaEng.createTarget(d);
	}

	@Override
	public FridaTarget connectSession(String fileName) {
		return FridaEng.createTarget(d);
	}

	@Override
	public Map<String, FridaSession> listSessions() {
		Map<String, FridaSession> map = new HashMap<>();
		//List<FridaTarget> targets = FridaEng.enumerateDevices(d);
		for (FridaTarget t : targets) {
			FridaSession session = t.getSession();
			if (session != null) {
				map.put(FridaClient.getId(session), session);
			}
		}
		return map;
	}

	@Override
	public void endSession(FridaTarget target, DebugEndSessionFlags flags) {
	}

	@Override
	public void processEvent(FridaEvent<?> fridaEvt) {
		manager.processEvent(fridaEvt);
	}

	@Override
	public DebugStatus getExecutionStatus() {
		FridaState state = manager.getState();
		return DebugStatus.fromArgument(state);
	}

	@Override
	public boolean getInterrupt() {
		return false;
	}

	@Override
	public void setManager(FridaManager manager) {
		this.manager = manager;
		manager.setCurrentTarget(initialTarget);
	}

}
