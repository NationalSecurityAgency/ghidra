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
package ghidra.app.plugin.core.instructionsearch.model;

import java.util.Observable;
import java.util.Observer;

import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;

/**
 * Interface for classes wishing to be notified when the {@link InstructionTable} is 
 * changed.
 * 
 * Note: This class is here since the basic {@link Observer} interface is not exactly
 * what we need.  It requires that any observables extend the {@link Observable} class, 
 * which we can't do since the precludes extending other classes we DO need.  Hence the
 * need for this custom implementation of the Observer pattern.  Note that we still take 
 * advantage of the {@link Observer} interface but only use part of its definition.
 *
 */
public interface InstructionTableObserver extends Observer {

	public void changed();
}
