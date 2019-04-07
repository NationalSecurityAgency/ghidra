/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.opinion;

public class IntelHexRecordReader {
    private static final int RECORD_MARK_START = 0;
    private static final int RECORD_MARK_END = 1;
    private static final int RECORD_LENGTH_START = 1;
    private static final int RECORD_LENGTH_END = 3;
    private static final int LOAD_OFFSET_START = 3;
    private static final int LOAD_OFFSET_END = 7;
    private static final int RECORD_TYPE_START = 7;
    private static final int RECORD_TYPE_END = 9;
    private static final int DATA_START = 9;
    private static final int CHECKSUM_LENGTH = 2;

    public static IntelHexRecord readRecord(String line) {
        line = line.replaceAll("\\s+", "");
        if (line.length() < DATA_START + CHECKSUM_LENGTH) {
            throw new IllegalArgumentException("line too short to contain record");
        }
        String recordMark = line.substring(RECORD_MARK_START, RECORD_MARK_END);
        if (!":".equals(recordMark)) {
            throw new IllegalArgumentException("line does not start with record mark (:)");
        }
        String recordLengthString = line.substring(RECORD_LENGTH_START, RECORD_LENGTH_END);
        int recordLength;
        try {
            recordLength = Integer.parseInt(recordLengthString, 16);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("error parsing record length: "
                    + e.getMessage());
        }
        String loadOffsetString = line.substring(LOAD_OFFSET_START, LOAD_OFFSET_END);
        int loadOffset;
        try {
            loadOffset = Integer.parseInt(loadOffsetString, 16);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("error parsing load offset: "
                    + e.getMessage());
        }
        String recordTypeString = line.substring(RECORD_TYPE_START, RECORD_TYPE_END);
        int recordType;
        try {
            recordType = Integer.parseInt(recordTypeString, 16);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("error parsing record type: "
                    + e.getMessage());
        }
        final int data_end = DATA_START + recordLength * 2;
        final int checksum_start = data_end;
        final int checksum_end = checksum_start + CHECKSUM_LENGTH;
        if (line.length() != checksum_end) {
            throw new IllegalArgumentException("line invalid length to contain record with record length "
                    + recordLength);
        }
        String dataString = line.substring(DATA_START, data_end);
        byte[] data = convertData(dataString);
        String checksumString = line.substring(checksum_start, checksum_end);
        int checksum;
        try {
            checksum = Integer.parseInt(checksumString, 16);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("error parsing checksum: "
                    + e.getMessage());
        }
        return new IntelHexRecord(recordLength, loadOffset, recordType, data, checksum);
    }

    private static byte[] convertData(String dataString) {
        if (dataString.length() % 2 == 1) {
            throw new IllegalArgumentException("internal error - data string of odd length");
        }
        byte[] result = new byte[dataString.length() / 2];
        for (int ii = 0, jj = 0; ii < dataString.length(); ii += 2, ++jj) {
            String bString = dataString.substring(ii, ii + 2);
            int b;
            try {
                b = Integer.parseInt(bString, 16);
            }
            catch (NumberFormatException e) {
                throw new IllegalArgumentException("error parsing data byte: "
                        + e.getMessage());
            }
            result[jj] = (byte) b;
        }
        return result;
    }
}
