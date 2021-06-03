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
package ghidra.app.services;

import java.lang.annotation.*;

import ghidra.framework.options.annotation.HelpInfo;

/**
 * Required information annotation on {@link DebuggerBot}s
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface DebuggerBotInfo {
	/**
	 * A quick one-line description of the actor
	 * 
	 * This is used as the option name to enable and disable the actor, to please, keep it short.
	 * Use {@link #details()} or {@link #help()} to provide more details.
	 * 
	 * @return the description
	 */
	String description();

	/**
	 * A longer description of this actor
	 * 
	 * A one-to-three-sentence detailed description of the actor. Again, it should be relatively
	 * short, as it used as the tool-tip popup in the plugin's options dialog. On some systems, such
	 * tips only display for a short time.
	 * 
	 * @return the detailed description
	 */
	String details();

	/**
	 * The location for help about this actor
	 * 
	 * Help is the best place to put lengthy descriptions of the actor and/or describe the caveats
	 * of using it. Since, in most cases, the actor is simply performing automatic actions, it is
	 * useful to show the reader how to perform those same actions manually. This way, if/when the
	 * actor takes an unreasonable action, the user can manually correct it.
	 * 
	 * @return the link to detailed help about the actor
	 */
	HelpInfo help() default @HelpInfo(topic = {});

	/**
	 * Check whether the actor should be enabled by default
	 * 
	 * For the stock plugin, a collection of actors should be enabled by default that make the
	 * debugger most accessible, erring toward ease of use, rather than toward correctness. Advanced
	 * users can always disable unwanted actors, tweak the options (TODO: Allow actors to present
	 * additional options in the tool config), and/or write their own actors and scripts.
	 * 
	 * For extensions, consider the user's expectations upon installing your extension. For example,
	 * if the extension consists of just an actor and some supporting classes, it should probably be
	 * enabled by default.
	 * 
	 * @return true to enable by default, false to leave disabled by default
	 */
	boolean enabledByDefault() default false;
}
