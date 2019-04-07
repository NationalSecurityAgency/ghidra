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
package ghidra.framework.task;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.DBHandle;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.AbortedTransactionListener;

public class GenericDomainObjectDB extends DomainObjectAdapterDB {
	String currentTransaction;
	List<String> transactionsList = new ArrayList<String>();

	public GenericDomainObjectDB(Object consumer) throws IOException {
		super(new DBHandle(), "Generic", 500, 1000, consumer);
	}

	@Override
	public String getDescription() {
		return "Generic Database Domain Object";
	}

	@Override
	public boolean isChangeable() {
		return false;
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener) {
		currentTransaction = description;
		return super.startTransaction(description, listener);
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		super.endTransaction(transactionID, commit);
		transactionsList.add(currentTransaction);
		currentTransaction = null;
	}
}
