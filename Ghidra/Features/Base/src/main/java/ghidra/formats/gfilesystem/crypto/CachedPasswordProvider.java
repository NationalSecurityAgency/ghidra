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
package ghidra.formats.gfilesystem.crypto;

import java.util.*;

import ghidra.formats.gfilesystem.FSRL;

/**
 * Caches passwords used to unlock a file.
 * <p>
 * Threadsafe.
 */
public class CachedPasswordProvider implements PasswordProvider {


	private Map<String, List<CryptoRec>> values = new HashMap<>();
	private int count;

	/**
	 * Adds a password / file combo to the cache.
	 * 
	 * @param fsrl {@link FSRL} file
	 * @param password password to unlock the file.  Specified PasswordValue is
	 * only copied, clearing is still callers responsibility
	 */
	public synchronized void addPassword(FSRL fsrl, PasswordValue password) {
		CryptoRec rec = new CryptoRec();
		rec.fsrl = fsrl;
		rec.value = password.clone();
		addRec(rec);
	}


	private void addRec(CryptoRec rec) {
		// index the record by its full FSRL, a simplified FSRL, its plain filename, and any MD5 
		String fsrlStr = rec.fsrl.toString();
		boolean isNewValue =
			addIfUnique(values.computeIfAbsent(fsrlStr, x -> new ArrayList<>()), rec);

		String fsrlStr2 = rec.fsrl.toPrettyString();
		if (!fsrlStr2.equals(fsrlStr)) {
			addIfUnique(values.computeIfAbsent(fsrlStr2, x -> new ArrayList<>()), rec);
		}

		addIfUnique(values.computeIfAbsent(rec.fsrl.getName(), x -> new ArrayList<>()), rec);

		if (rec.fsrl.getMD5() != null) {
			addIfUnique(values.computeIfAbsent(rec.fsrl.getMD5(), x -> new ArrayList<>()), rec);
		}

		if (isNewValue) {
			count++;
		}
	}

	private boolean addIfUnique(List<CryptoRec> recs, CryptoRec newRec) {
		for (CryptoRec rec : recs) {
			if (rec.value.equals(newRec.value)) {
				return false;
			}
		}
		recs.add(newRec);
		return true;
	}

	/**
	 * Remove all cached information.
	 */
	public synchronized void clearCache() {
		values.clear();
		count = 0;
	}

	/**
	 * Returns the number of items in cache
	 * 
	 * @return number of items in cache
	 */
	public synchronized int getCount() {
		return count;
	}

	@Override
	public synchronized Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt,
			Session session) {
		Set<CryptoRec> uniqueFoundRecs = new LinkedHashSet<>();
		uniqueFoundRecs.addAll(values.getOrDefault(fsrl.toString(), Collections.emptyList()));
		uniqueFoundRecs.addAll(values.getOrDefault(fsrl.toPrettyString(), Collections.emptyList()));
		uniqueFoundRecs.addAll(values.getOrDefault(fsrl.getName(), Collections.emptyList()));
		if (fsrl.getMD5() != null) {
			uniqueFoundRecs.addAll(values.getOrDefault(fsrl.getMD5(), Collections.emptyList()));
		}

		List<PasswordValue> results = new ArrayList<>();
		for (CryptoRec rec : uniqueFoundRecs) {
			results.add(rec.value);
		}

		// Use an iterator that clones the values before giving them to the caller
		// so our internal values don't get cleared
		return new CloningPasswordIterator(results.iterator());
	}

	private static class CryptoRec {
		FSRL fsrl;
		PasswordValue value;
	}

	private class CloningPasswordIterator implements Iterator<PasswordValue> {
		Iterator<PasswordValue> delegate;

		CloningPasswordIterator(Iterator<PasswordValue> it) {
			this.delegate = it;
		}

		@Override
		public boolean hasNext() {
			return delegate.hasNext();
		}

		@Override
		public PasswordValue next() {
			PasswordValue result = delegate.next();
			return result.clone();
		}

	}

}
