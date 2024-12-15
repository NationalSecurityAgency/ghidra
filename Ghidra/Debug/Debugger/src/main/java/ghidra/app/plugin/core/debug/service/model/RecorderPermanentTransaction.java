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
package ghidra.app.plugin.core.debug.service.model;

import db.Transaction;
import ghidra.framework.model.DomainObject;

@Deprecated(forRemoval = true, since = "11.3")
public class RecorderPermanentTransaction implements AutoCloseable {

	public static RecorderPermanentTransaction start(DomainObject obj, String description) {
		Transaction tx = obj.openTransaction(description);
		return new RecorderPermanentTransaction(obj, tx);
	}

	private final DomainObject obj;
	private final Transaction tx;

	public RecorderPermanentTransaction(DomainObject obj, Transaction tx) {
		this.obj = obj;
		this.tx = tx;
	}

	@Override
	public void close() {
		tx.close();
		obj.clearUndo();
	}
}
