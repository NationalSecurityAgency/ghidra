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
package ghidra.dbg.target;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * Provides information about a given target object
 * 
 * <p>
 * This is mostly a marker interface so that the client knows where to look for information about a
 * target. This may be attached to the entire session, or it may be attached to individual targets
 * in a session. The information is generally encoded as string-valued attributes, for which this
 * interface provides convenient accessors. The form of the strings is not strictly specified. They
 * should generally just take verbatim whatever string the host debugger would use to describe the
 * platform. It is up to the client to interpret the information into an equivalent specification in
 * the UI/database.
 * 
 * @implNote to simplify the automatic choice of mapper when recording a trace, it is required to
 *           update a target's environment attributes before reporting that it has started. Relaxing
 *           this requirement is TODO. Note that targets which do not support
 *           {@link TargetExecutionStateful} are assumed started by virtue of their creation.
 */
@DebuggerTargetObjectIface("Environment")
public interface TargetEnvironment extends TargetObject {

	String ARCH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "arch";
	String DEBUGGER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "debugger";
	String OS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "os";
	String ENDIAN_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "endian";

	/**
	 * Get a description of the target architecture
	 * 
	 * <p>
	 * This should be as specific a description of the processor as possible. Ideally, the processor
	 * family is apparent in the description. The client will interpret this to determine the
	 * appropriate Instruction Set Architecture and any nuances in the processor's behavior. For
	 * example {@code family:version:variant}. If the debugger has its own format for these
	 * descriptors, please use it.
	 * 
	 * @return the target architecture
	 */
	@TargetAttributeType(name = ARCH_ATTRIBUTE_NAME, hidden = true)
	default String getArchitecture() {
		return getTypedAttributeNowByName(ARCH_ATTRIBUTE_NAME, String.class, "");
	}

	/**
	 * Get a description of the debugger
	 * 
	 * <p>
	 * This should be as specific a description of the debugger as possible. Ideally, the debugger's
	 * name is apparent in the description. The client may use this to properly interpret the other
	 * environment descriptors. For example {@code GNU gdb (GDB) 8.0}. While version and additional
	 * platform information may be presented, clients should avoid relying on it, esp., to account
	 * for nuances in debugger behavior. The model implementation (i.e., the "agent") is responsible
	 * for presenting a model consistent with the debugger's behavior.
	 * 
	 * @return the host debugger
	 */
	@TargetAttributeType(name = DEBUGGER_ATTRIBUTE_NAME, hidden = true)
	default String getDebugger() {
		return getTypedAttributeNowByName(DEBUGGER_ATTRIBUTE_NAME, String.class, "");
	}

	/**
	 * Get a description of the target operating system
	 * 
	 * <p>
	 * This should be as specific a description of the operating system as possible. Ideally, the OS
	 * name is apparent in the description. The client will interpret this to determine the
	 * appropriate Application Binary Interface. For example {@code GNU/Linux}. The client may also
	 * use this to decide how to interpret other information present in the model, e.g., file system
	 * paths.
	 * 
	 * @return the target operating system
	 */
	@TargetAttributeType(name = OS_ATTRIBUTE_NAME, hidden = true)
	default String getOperatingSystem() {
		return getTypedAttributeNowByName(OS_ATTRIBUTE_NAME, String.class, "");
	}

	/**
	 * Get the endianness of the target
	 * 
	 * <p>
	 * In most cases, a simple "little" or "big" should do, but there may exist cases where code is
	 * in one form and data is in another. For those, choose something recognizable to someone
	 * writing an opinion for tracing the target. TODO: Formalize those conventions?
	 * 
	 * @return the target endianness
	 */
	@TargetAttributeType(name = ENDIAN_ATTRIBUTE_NAME, hidden = true)
	default String getEndian() {
		return getTypedAttributeNowByName(ENDIAN_ATTRIBUTE_NAME, String.class, "");
	}

	// TODO: Devices? File System?
}
