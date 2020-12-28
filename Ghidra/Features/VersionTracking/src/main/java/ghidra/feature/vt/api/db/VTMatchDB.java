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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTMatchTableDBAdapter.ColumnDescription.*;

import java.io.IOException;

import db.DBRecord;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.*;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.Address;
import ghidra.util.Lock;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

public class VTMatchDB extends DatabaseObject implements VTMatch {

	private DBRecord record;
	private final VTMatchSetDB matchSet;
	private VTSessionDB session;
	private VTAssociation association;

	protected Lock lock;

	private boolean doCalculateHash = true;
	private int hash;

	public VTMatchDB(DBObjectCache<VTMatchDB> cache, DBRecord record, VTMatchSetDB matchSet) {
		super(cache, record.getKey());
		this.record = record;
		this.matchSet = matchSet;
		session = (VTSessionDB) matchSet.getSession();
		lock = session.getLock();
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord matchRecord) {
		association = null;
		if (matchRecord == null) {
			matchRecord = matchSet.getMatchRecord(key);
		}
		if (matchRecord == null) {
			return false;
		}
		record = matchRecord;
		return true;
	}

	@Override
	public VTMatchSet getMatchSet() {
		return matchSet;
	}

	@Override
	public int getDestinationLength() {
		return record.getIntValue(DESTINATION_LENGTH_COL.column());
	}

	@Override
	public VTScore getSimilarityScore() {
		return new VTScore(record.getString(SIMILARITY_SCORE_COL.column()));
	}

	@Override
	public VTScore getConfidenceScore() {
		return new VTScore(record.getString(CONFIDENCE_SCORE_COL.column()));
	}

	public String getLengthType() {
		return record.getString(LENGTH_TYPE.column());
	}

	@Override
	public int getSourceLength() {
		return record.getIntValue(SOURCE_LENGTH_COL.column());
	}

	@Override
	public VTMatchTag getTag() {
		long tagKey = record.getLongValue(TAG_KEY_COL.column());
		return session.getMatchTag(tagKey);
	}

	@Override
	public void setTag(VTMatchTag tag) {
		lock.acquire();
		try {
			checkDeleted();
			if (record == null) {
				return;
			}

			VTMatchTag oldTag = getTag();
			if (SystemUtilities.isEqual(tag, oldTag)) {
				return;
			}

			long tagKey = -1;
			VTMatchTagDB newTagDB = session.getOrCreateMatchTagDB(tag);
			if (newTagDB != null) {
				tagKey = newTagDB.getKey();
			}

			record.setLongValue(TAG_KEY_COL.column(), tagKey);
			updateRecord();
			session.setObjectChanged(VTChangeManager.DOCR_VT_MATCH_TAG_CHANGED, this, oldTag,
				newTagDB);
		}
		finally {
			lock.release();
		}
	}

	private VTAssociation loadAssociation() {
		long associationKey = record.getLongValue(ASSOCIATION_COL.column());
		AssociationDatabaseManager associationManager = matchSet.getAssociationManager();
		VTAssociation existingAssociation = associationManager.getAssociation(associationKey);
		if (existingAssociation == null) {
			throw new AssertException("This match has no VTAssociation!");
		}

		return existingAssociation;
	}

	@Override
	public VTAssociation getAssociation() {
		lock.acquire();
		try {
			checkIsValid();
			if (association == null) {
				association = loadAssociation();
			}
		}
		finally {
			lock.release();
		}
		return association;
	}

	private void updateRecord() {
		VTMatchTableDBAdapter matchTableAdapter = matchSet.getMatchTableAdapter();
		try {
			matchTableAdapter.updateRecord(record);
		}
		catch (IOException e) {
			matchSet.dbError(e);
		}
	}

	@Override
	public int hashCode() {
		if (doCalculateHash) {
			hash = 17;
			Address sourceAddress = getAssociation().getSourceAddress();
			if (sourceAddress != null) {
				hash = 37 * hash + (int) sourceAddress.getOffset();
			}

			Address destinationAddress = getAssociation().getDestinationAddress();
			if (destinationAddress != null) {
				hash = 37 * hash + (int) destinationAddress.getOffset();
			}

			VTProgramCorrelatorInfo info = getMatchSet().getProgramCorrelatorInfo();
			String programCorrelatorName = info.getName();
			if (programCorrelatorName != null) {
				hash = 37 * hash + programCorrelatorName.hashCode();
			}
			doCalculateHash = false;
		}

		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof VTMatch)) {
			return false;
		}

		VTMatchDB other = (VTMatchDB) obj;

		if (matchSet.getID() != other.matchSet.getID()) {
			return false;
		}

		if (getSourceLength() != other.getSourceLength()) {
			return false;
		}

		if (getDestinationLength() != other.getDestinationLength()) {
			return false;
		}

		if (!SystemUtilities.isEqual(getSimilarityScore(), other.getSimilarityScore())) {
			return false;
		}

		if (!SystemUtilities.isEqual(getConfidenceScore(), other.getConfidenceScore())) {
			return false;
		}

		if (getTag() != other.getTag()) {
			return false;
		}

		if (!SystemUtilities.isEqual(getAssociation(), other.getAssociation())) {
			return false;
		}
		return true;
	}

	@Override
	public Address getSourceAddress() {
		return getAssociation().getSourceAddress();
	}

	@Override
	public Address getDestinationAddress() {
		return getAssociation().getDestinationAddress();
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();

		Address destinationAddress = getDestinationAddress();
		Address sourceAddress = getSourceAddress();
		double similarityScore = getSimilarityScore().getScore();
		double confidenceScore = getConfidenceScore().getScore();

		buffer.append("\nMatch:");
		buffer.append("\n  Type               = ").append(getAssociation().getType());
		buffer.append("\n  Similarity Score   = ").append(similarityScore);
		buffer.append("\n  Confidence Score   = ").append(confidenceScore);
		buffer.append("\n  SourceAddress      = ").append(sourceAddress);
		buffer.append("\n  DestinationAddress = ").append(destinationAddress);
		buffer.append("\n  LengthType         = ").append(getLengthType());
		buffer.append("\n  SourceLength       = ").append(getSourceLength());
		buffer.append("\n  DestinationLength  = ").append(getDestinationLength());
		buffer.append("\n  Tagged             = ").append(getTag());
		buffer.append("\n  Session ID:        = ").append(matchSet.getID());
		return buffer.toString();
	}
}
