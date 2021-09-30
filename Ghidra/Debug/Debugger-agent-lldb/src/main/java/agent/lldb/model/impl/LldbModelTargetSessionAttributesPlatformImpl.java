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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.model.iface2.LldbModelTargetSessionAttributes;
import agent.lldb.model.iface2.LldbModelTargetSessionAttributesPlatform;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SessionAttributesPlatform",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	})
public class LldbModelTargetSessionAttributesPlatformImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSessionAttributesPlatform {

	static String ARCH_ATTRIBUTE_NAME = "Arch";
	static String MANUFACTURER_ATTRIBUTE_NAME = "Manufacturer";
	static String OS_ATTRIBUTE_NAME = "OS";
	static String OS_MM_ATTRIBUTE_NAME = "Major:Minor";
	static String OS_DESC_ATTRIBUTE_NAME = "Description";
	static String DEBUGGER_ATTRIBUTE_NAME = "Debugger";
	static String BUILD_ATTRIBUTE_NAME = "Build";
	static String ENDIAN_ATTRIBUTE_NAME = "Endian";
	static String DIRECTORY_ATTRIBUTE_NAME = "Working Dir";

	SBTarget session;

	public LldbModelTargetSessionAttributesPlatformImpl(
			LldbModelTargetSessionAttributes attributes) {
		super(attributes.getModel(), attributes, "Platform", "SessionAttributesPlatform");

		session = (SBTarget) getModelObject();
		String[] triple = session.GetTriple().split("-");
		ByteOrder order = session.GetByteOrder();
		SBPlatform platform = session.GetPlatform();

		long major = platform.GetOSMajorVersion();
		long minor = platform.GetOSMinorVersion();
		String build = platform.GetOSBuild();
		if (build == null) {
			build = "unknown";
		}
		String desc = platform.GetOSDescription();
		if (desc == null) {
			desc = "unknown";
		}
		String wdir = platform.GetWorkingDirectory();

		changeAttributes(List.of(), List.of(), Map.of( //
			ARCH_ATTRIBUTE_NAME, triple[0], //
			MANUFACTURER_ATTRIBUTE_NAME, triple[1], //
			OS_ATTRIBUTE_NAME, triple[2], //
			OS_DESC_ATTRIBUTE_NAME, desc, //
			DEBUGGER_ATTRIBUTE_NAME, "lldb", //
			OS_MM_ATTRIBUTE_NAME, major + ":" + minor, //
			BUILD_ATTRIBUTE_NAME, build, //
			ENDIAN_ATTRIBUTE_NAME, order.toString(), //
			DIRECTORY_ATTRIBUTE_NAME, wdir //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void sessionAdded(SBTarget session, LldbCause cause) {
		refreshInternal();
	}

	@Override
	public void processAdded(SBProcess process, LldbCause cause) {
		SBTarget procTarget = process.GetTarget();
		if (!DebugClient.getId(session).equals(DebugClient.getId(procTarget))) {
			return;
		}
		refreshInternal();
	}

	public void refreshInternal() {
		AtomicReference<String> capture = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().consoleCapture("version").handle(seq::next);
		}, capture).then(seq -> {
			changeAttributes(List.of(), List.of(), Map.of( //
				DEBUGGER_ATTRIBUTE_NAME, capture.get()), "Refreshed");
		}).finish();
	}

}
