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
package ghidra.app.plugin.core.debug.service.model.launch;

import java.lang.annotation.*;
import java.lang.invoke.*;
import java.lang.invoke.MethodHandles.Lookup;
import java.util.*;

import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public abstract class AbstractDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {
	protected static final Lookup LOOKUP = MethodHandles.lookup();
	protected static final MethodType CON_SIG = MethodType.methodType(void.class, Program.class,
		PluginTool.class, DebuggerModelFactory.class);

	@Target(ElementType.TYPE)
	@Retention(RetentionPolicy.RUNTIME)
	protected @interface FactoryClass {
		String value();
	}

	protected static DebuggerModelFactory getFactory(
			Class<? extends DebuggerProgramLaunchOffer> offerClass, DebuggerModelService service) {
		FactoryClass annotation = offerClass.getAnnotation(FactoryClass.class);
		if (annotation == null) {
			Msg.error(AbstractDebuggerProgramLaunchOpinion.class,
				"Missing @" + FactoryClass.class.getSimpleName() + " annotation on " + offerClass);
			return null;
		}
		Optional<DebuggerModelFactory> found = service.getModelFactories()
				.stream()
				.filter(f -> f.getClass().getName().equals(annotation.value()))
				.findAny();
		if (found.isEmpty()) {
			Msg.error(AbstractDebuggerProgramLaunchOpinion.class,
				"No factory with name " + annotation.value() + " required by " + offerClass);
			return null;
		}
		return found.get();
	}

	protected abstract Collection<Class<? extends DebuggerProgramLaunchOffer>> getOfferClasses();

	@Override
	public Collection<DebuggerProgramLaunchOffer> getOffers(Program program, PluginTool tool,
			DebuggerModelService service) {
		String exe = program.getExecutablePath();
		if (exe == null || exe.isBlank()) {
			return List.of();
		}
		List<DebuggerProgramLaunchOffer> offers = new ArrayList<>();
		for (Class<? extends DebuggerProgramLaunchOffer> cls : getOfferClasses()) {
			DebuggerModelFactory factory = getFactory(cls, service);
			if (factory == null || !factory.isCompatible(program)) {
				continue;
			}
			try {
				MethodHandle constructor = LOOKUP.findConstructor(cls, CON_SIG);
				offers.add((DebuggerProgramLaunchOffer) constructor.invoke(program, tool, factory));
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		}
		return offers;
	}

}
