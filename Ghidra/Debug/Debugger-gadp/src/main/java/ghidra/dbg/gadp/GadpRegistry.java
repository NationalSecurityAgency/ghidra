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
package ghidra.dbg.gadp;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.google.protobuf.Message;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.gadp.client.*;
import ghidra.dbg.target.*;
import utilities.util.reflection.ReflectionUtilities;

public enum GadpRegistry {
	;

	public interface InvocationBuilder {
		Message.Builder buildMessage(String oid, Object[] args);
	}

	public interface ServerInvoker<M> {
		CompletableFuture<Message.Builder> invoke(TargetObject object, M msg);
	}

	public static final Map<Class<? extends TargetObject>, Class<? extends TargetObject>> MIXIN_REGISTRY =
		new HashMap<>();

	public static <T extends TargetObject> void registerInterface(Class<T> iface,
			Class<? extends T> mixin) {
		DebuggerObjectModel.requireIfaceName(iface);
		MIXIN_REGISTRY.put(iface, mixin);
	}

	static {
		registerInterface(TargetAccessConditioned.class, GadpClientTargetAccessConditioned.class);
		registerInterface(TargetAggregate.class, GadpClientTargetAggregate.class);
		registerInterface(TargetAttachable.class, GadpClientTargetAttachable.class);
		registerInterface(TargetAttacher.class, GadpClientTargetAttacher.class);
		registerInterface(TargetBreakpointLocation.class, GadpClientTargetBreakpointLocation.class);
		registerInterface(TargetBreakpointLocationContainer.class,
			GadpClientTargetBreakpointLocationContainer.class);
		registerInterface(TargetBreakpointSpecContainer.class,
			GadpClientTargetBreakpointSpecContainer.class);
		registerInterface(TargetBreakpointSpec.class, GadpClientTargetBreakpointSpec.class);
		registerInterface(TargetConfigurable.class, GadpClientTargetConfigurable.class);
		registerInterface(TargetConsole.class, GadpClientTargetConsole.class);
		registerInterface(TargetDataTypeMember.class, GadpClientTargetDataTypeMember.class);
		registerInterface(TargetDataTypeNamespace.class, GadpClientTargetDataTypeNamespace.class);
		registerInterface(TargetDeletable.class, GadpClientTargetDeletable.class);
		registerInterface(TargetDetachable.class, GadpClientTargetDetachable.class);
		registerInterface(TargetEnvironment.class, GadpClientTargetEnvironment.class);
		registerInterface(TargetEventScope.class, GadpClientTargetEventScope.class);
		registerInterface(TargetExecutionStateful.class, GadpClientTargetExecutionStateful.class);
		registerInterface(TargetActiveScope.class, GadpClientTargetActiveScope.class);
		registerInterface(TargetFocusScope.class, GadpClientTargetFocusScope.class);
		registerInterface(TargetInterpreter.class, GadpClientTargetInterpreter.class);
		registerInterface(TargetInterruptible.class, GadpClientTargetInterruptible.class);
		registerInterface(TargetKillable.class, GadpClientTargetKillable.class);
		registerInterface(TargetLauncher.class, GadpClientTargetLauncher.class);
		registerInterface(TargetMethod.class, GadpClientTargetMethod.class);
		registerInterface(TargetMemory.class, GadpClientTargetMemory.class);
		registerInterface(TargetMemoryRegion.class, GadpClientTargetMemoryRegion.class);
		registerInterface(TargetModule.class, GadpClientTargetModule.class);
		registerInterface(TargetModuleContainer.class, GadpClientTargetModuleContainer.class);
		registerInterface(TargetNamedDataType.class, GadpClientTargetNamedDataType.class);
		registerInterface(TargetProcess.class, GadpClientTargetProcess.class);
		registerInterface(TargetRegister.class, GadpClientTargetRegister.class);
		registerInterface(TargetRegisterBank.class, GadpClientTargetRegisterBank.class);
		registerInterface(TargetRegisterContainer.class, GadpClientTargetRegisterContainer.class);
		registerInterface(TargetResumable.class, GadpClientTargetResumable.class);
		registerInterface(TargetSection.class, GadpClientTargetSection.class);
		registerInterface(TargetSectionContainer.class, GadpClientTargetSectionContainer.class);
		registerInterface(TargetStack.class, GadpClientTargetStack.class);
		registerInterface(TargetStackFrame.class, GadpClientTargetStackFrame.class);
		registerInterface(TargetSteppable.class, GadpClientTargetSteppable.class);
		registerInterface(TargetSymbol.class, GadpClientTargetSymbol.class);
		registerInterface(TargetSymbolNamespace.class, GadpClientTargetSymbolNamespace.class);
		registerInterface(TargetThread.class, GadpClientTargetThread.class);
		registerInterface(TargetTogglable.class, GadpClientTargetTogglable.class);
	}

	public static List<Class<? extends TargetObject>> getMixins(
			List<Class<? extends TargetObject>> ifaces) {
		return ifaces.stream().map(MIXIN_REGISTRY::get).collect(Collectors.toList());
	}

	public static List<String> getInterfaceNames(TargetObject obj) {
		List<String> result = new ArrayList<>();
		for (Class<?> parent : ReflectionUtilities.getAllParents(obj.getClass())) {
			DebuggerTargetObjectIface annot = parent.getAnnotation(DebuggerTargetObjectIface.class);
			if (annot != null) {
				result.add(annot.value());
			}
		}
		return result;
	}
}
