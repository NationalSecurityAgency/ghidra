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
package ghidra.app.plugin.core.debug.mapping;

import db.Transaction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;

public class DefaultDebuggerPlatformMapper extends AbstractDebuggerPlatformMapper {

	protected static boolean isHarvard(Language language) {
		return language.getDefaultSpace() != language.getDefaultDataSpace();
	}

	protected final PluginTool tool;
	protected final CompilerSpec cSpec;

	public DefaultDebuggerPlatformMapper(PluginTool tool, Trace trace, CompilerSpec cSpec) {
		super(tool, trace);
		validate(cSpec);
		this.tool = tool;
		this.cSpec = cSpec;
	}

	protected void validate(CompilerSpec cSpec) {
		if (isHarvard(cSpec.getLanguage())) {
			throw new IllegalArgumentException("This mapper cannot handle Harvard guests");
		}
	}

	@Override
	public CompilerSpec getCompilerSpec(TraceObject object) {
		return cSpec;
	}

	@Override
	public void addToTrace(long snap) {
		String description = "Add guest " + cSpec.getLanguage().getLanguageDescription() + "/" +
			cSpec.getCompilerSpecDescription();
		try (Transaction tx = trace.openTransaction(description)) {
			TracePlatformManager platformManager = trace.getPlatformManager();
			TracePlatform platform = platformManager.getOrAddPlatform(cSpec);
			if (platform.isHost()) {
				return;
			}
			addMappedRanges((TraceGuestPlatform) platform);
		}
	}

	/**
	 * Add mapped ranges if not already present
	 * 
	 * <p>
	 * A transaction is already started when this method is invoked.
	 * 
	 * @param platform the platform
	 */
	protected void addMappedRanges(TraceGuestPlatform platform) {
		Trace trace = platform.getTrace();
		AddressSpace hostSpace = trace.getBaseAddressFactory().getDefaultAddressSpace();
		AddressSpace guestSpace = platform.getAddressFactory().getDefaultAddressSpace();
		long min = MathUtilities.unsignedMax(hostSpace.getMinAddress().getOffset(),
			guestSpace.getMinAddress().getOffset());
		long max = MathUtilities.unsignedMin(hostSpace.getMaxAddress().getOffset(),
			guestSpace.getMaxAddress().getOffset());
		Address hostStart = hostSpace.getAddress(min);
		Address guestStart = guestSpace.getAddress(min);

		/*
		 * TODO: I could perhaps do better, but assuming I'm the only source of mappings, this
		 * should suffice.
		 */
		if (platform.getHostAddressSet().contains(hostStart)) {
			return;
		}
		try {
			platform.addMappedRange(hostStart, guestStart, max - min + 1);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}

		try {
			platform.addMappedRegisterRange();
		}
		catch (AddressOverflowException e) {
			Msg.showError(this, null, "Map Registers",
				"The host language cannot accomodate register storage for the" +
					" guest platform (language: " + platform.getLanguage() + ")");
		}
	}
}
