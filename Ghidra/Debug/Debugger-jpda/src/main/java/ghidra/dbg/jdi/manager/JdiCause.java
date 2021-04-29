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
package ghidra.dbg.jdi.manager;

/**
 * Identifies the cause of an event emitted by JDI
 * 
 * This is not a concept native to JDI. Rather, it is a means to distinguish events that result from
 * commands issued by the {@link JdiManager} from those issued by the user or some other means. For
 * example, a call to {@link JdiManager#addInferior()} will emit a
 * {@link JdiEventsListener#inferiorAdded(JdiVM, JdiCause)} event, identifying the
 * {@link JdiPendingCommand} as the cause. However, a call to {@link JdiManager#console(String)}
 * issuing an "add-inferior" command will emit the same event, but the cause will be
 * {@link JdiCause.Causes#UNCLAIMED}.
 */
public interface JdiCause {
	public enum Causes implements JdiCause {
		UNCLAIMED;
	}
}
