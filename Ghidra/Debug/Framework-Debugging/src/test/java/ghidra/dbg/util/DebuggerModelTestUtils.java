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
package ghidra.dbg.util;

import java.util.Map;

import ghidra.async.AsyncTestUtils;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AllRequiredAccess;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;

public interface DebuggerModelTestUtils extends AsyncTestUtils {

	default TargetObject root(DebuggerObjectModel model) throws Throwable {
		return waitOn(model.fetchModelRoot());
	}

	default <T extends TargetObject> T suitable(Class<T> type, TargetObject seed)
			throws Throwable {
		return waitOn(DebugModelConventions.findSuitable(type, seed));
	}

	default AllRequiredAccess access(TargetObject obj) throws Throwable {
		return waitOn(DebugModelConventions.trackAccessibility(obj));
	}

	default void waitAcc(AllRequiredAccess access) throws Throwable {
		waitOn(access.waitValue(TargetAccessibility.ACCESSIBLE));
	}

	default void cli(TargetObject interpreter, String cmd) throws Throwable {
		TargetInterpreter<?> as = interpreter.as(TargetInterpreter.tclass);
		waitOn(as.execute(cmd));
	}

	default String captureCli(TargetObject interpreter, String cmd) throws Throwable {
		TargetInterpreter<?> as = interpreter.as(TargetInterpreter.tclass);
		return waitOn(as.executeCapture(cmd));
	}

	default void launch(TargetObject launcher, Map<String, ?> args) throws Throwable {
		TargetLauncher<?> as = launcher.as(TargetLauncher.tclass);
		waitOn(as.launch(args));
	}

	default void resume(TargetObject resumable) throws Throwable {
		TargetResumable<?> as = resumable.as(TargetResumable.tclass);
		waitOn(as.resume());
	}

	default void step(TargetObject steppable, TargetStepKind kind) throws Throwable {
		TargetSteppable<?> as = steppable.as(TargetSteppable.tclass);
		waitOn(as.step(kind));
	}

	default TargetObjectRef getFocus(TargetObject scope) {
		TargetFocusScope<?> as = scope.as(TargetFocusScope.tclass);
		return as.getFocus();
	}

	default void focus(TargetObject scope, TargetObjectRef focus) throws Throwable {
		TargetFocusScope<?> as = scope.as(TargetFocusScope.tclass);
		waitOn(as.requestFocus(focus));
	}

}
