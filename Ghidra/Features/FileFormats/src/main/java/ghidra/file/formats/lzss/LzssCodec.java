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
package ghidra.file.formats.lzss;

import java.io.*;
import java.nio.ByteBuffer;

/**
 * Based on the lzss.c source in img4lib
 * 
 * **************************************************************
 * 
 * LZSS.C -- A Data Compression Program
 * 
 * **************************************************************
 * 
 * 4/6/1989 Haruhiko Okumura
 * 
 * Use, distribution, and modify this program freely.
 * 
 * Please send me your improved versions.
 * 
 * PC-VAN SCIENCE
 * 
 * NIFTY-Serve PAF01022
 * 
 * CompuServe 74050,1022
 *
 **************************************************************/
public class LzssCodec {

	static int unsigned(byte b) {
		return b < 0 ? b + 256 : b;
	}

	/** size of ring buffer - must be power of 2 */
	public static final int N = 4096;
	/** upper limit for match_length */
	public static final int F = 18;
	/**
	 * encode string into position and length if match_length is greater than
	 * this
	 */
	public static final int THRESHOLD = 2;
	/** index for root of binary search trees */
	public static final int NIL = N;

	private static class EncodeState {
		/**
		 * initialize state, mostly the trees
		 * 
		 * For i = 0 to N - 1, rchild[i] and lchild[i] will be the right and
		 * left children of node i. These nodes need not be initialized. Also
		 * parent[i] is the parent of node i. These are initialzied to NIL (=N),
		 * which stands for 'not used.' For i = 0 to 256, rchild[N + i + 1] is
		 * the root of the tree for strings that begin with character i. These
		 * are initialized to NIL. Note there are 256 trees.
		 */
		public EncodeState() {
			for (int i = 0; i < N - F; i++) {
				textBuf.put((byte) ' ');
			}
			for (int i = N + 1; i <= N + 256; i++) {
				rchild[i] = NIL;
			}
			for (int i = 0; i < N; i++) {
				parent[i] = NIL;
			}
		}

		/* These constitute binary search trees */
		int lchild[] = new int[N + 1];
		int rchild[] = new int[N + 257];
		int parent[] = new int[N + 1];

		/* Ring buffer of size N, with extra F-1 bytes to aid string comparison */
		ByteBuffer textBuf = ByteBuffer.allocate(N + F - 1);

		int matchPosition;
		int matchLength;

		void insertNode(int r) {
			int i, p, cmp;

			cmp = 1;
			p = N + 1 + unsigned(textBuf.get(r));
			rchild[r] = lchild[r] = NIL;
			matchLength = 0;
			for (;;) { // Enter the walrus
				if (cmp >= 0) {
					if (rchild[p] != NIL) {
						p = rchild[p];
					}
					else {
						rchild[p] = r;
						parent[r] = p;
						return;
					}
				}
				else {
					if (lchild[p] != NIL) {
						p = lchild[p];
					}
					else {
						lchild[p] = r;
						parent[r] = p;
						return;
					}
				}
				for (i = 1; i < F; i++) {
					if ((cmp = unsigned(textBuf.get(r + i)) - unsigned(textBuf.get(p + i))) != 0) {
						break;
					}
				}
				if (i > matchLength) {
					matchPosition = p;
					if ((matchLength = i) >= F) {
						break;
					}
				}
			}
			parent[r] = parent[p];
			lchild[r] = lchild[p];
			rchild[r] = rchild[p];
			parent[lchild[p]] = r;
			parent[rchild[p]] = r;
			if (rchild[parent[p]] == p) {
				rchild[parent[p]] = r;
			}
			else {
				lchild[parent[p]] = r;
			}
			parent[p] = NIL; /* remove p */
		}

		void deleteNode(int p) {
			int q;

			if (parent[p] == NIL) {
				return; /* not in tree */
			}
			if (rchild[p] == NIL) {
				q = lchild[p];
			}
			else if (lchild[p] == NIL) {
				q = rchild[p];
			}
			else {
				q = lchild[p];
				if (rchild[q] != NIL) {
					do {
						q = rchild[q];
					}
					while (rchild[q] != NIL);
					rchild[parent[q]] = lchild[q];
					parent[lchild[q]] = parent[q];
					lchild[q] = lchild[p];
					parent[lchild[p]] = q;
				}
				rchild[q] = rchild[p];
				parent[rchild[p]] = q;
			}
			parent[q] = parent[p];
			if (rchild[parent[p]] == p) {
				rchild[parent[p]] = q;
			}
			else {
				lchild[parent[p]] = q;
			}
			parent[p] = NIL;
		}
	}

	public static void decompress(OutputStream dst, InputStream src) throws IOException {
		/* Ring buffer of size N, with extra F-1 bytes to aid string comparison */
		ByteBuffer textBuf = ByteBuffer.allocate(N + F - 1);

		int flags;

		for (int i = 0; i < N - F; i++) {
			textBuf.put((byte) ' ');
		}
		textBuf.position(N - F);
		flags = 0;
		for (;;) {
			if (((flags >>>= 1) & 0x100) == 0) {
				int c = src.read();
				if (c == -1) {
					break;
				}
				flags = c | 0xFF00; /* uses higher byte cleverly */
			} /* count to eight */
			if ((flags & 1) != 0) {
				int c = src.read();
				if (c == -1) {
					break;
				}
				dst.write(c);
				textBuf.put((byte) c);
				textBuf.position(textBuf.position() & (N - 1));
			}
			else {
				int i = src.read();
				if (i == -1) {
					break;
				}
				int j = src.read();
				if (j == -1) {
					break;
				}
				i |= ((j & 0xF0) << 4);
				j = (j & 0x0F) + THRESHOLD;
				for (int k = 0; k <= j; k++) {
					int c = textBuf.get((i + k) & (N - 1));
					dst.write(c);
					textBuf.put((byte) c);
					textBuf.position(textBuf.position() & (N - 1));
				}
			}
		}
		dst.flush();
	}

	public static void compress(OutputStream dst, InputStream src) throws IOException {
		/* Encoding state, mostly trees but some current match stuff */
		EncodeState sp;

		int i, c, len, r, s, lastMatchLength;
		ByteBuffer codeBuf = ByteBuffer.allocate(17);
		byte mask;

		/* initialize trees */
		sp = new EncodeState();

		/*
		 * code_buf[1..16] saves eight units of code, and code_buf[0] works as
		 * eight flags, "1" representing that the unit is an unencoded letter (1
		 * byte), "" a position-and-length pair (2 bytes). Thus, either units
		 * require at most 16 bytes of code.
		 */
		codeBuf.put((byte) 0);
		mask = 1;

		/* Clear the buffer with any character that will appear often. */
		s = 0;
		r = N - F;

		/* Read F bytes into the last F bytes of the buffer */
		for (len = 0; len < F; len++) {
			int b = src.read();
			if (b == -1) {
				break;
			}
			sp.textBuf.put(r + len, (byte) b);
		}
		if (len == 0) {
			return; /* text of size zero */
		}
		/*
		 * Insert the F strings, each of which begins with one or more 'space'
		 * characters. Note the order in which these strings are inserted. This
		 * way degenerate trees will be less likely to occur.
		 */
		for (i = 1; i <= F; i++) {
			sp.insertNode(r - i);
		}

		/*
		 * Finally, insert the whole string just read. The global variables
		 * match_length and match_position are set.
		 */
		sp.insertNode(r);
		do {
			/* match_length may be spuriously long near the end of text. */
			if (sp.matchLength > len) {
				sp.matchLength = len;
			}
			if (sp.matchLength <= THRESHOLD) {
				sp.matchLength = 1; /* Not long enough match. Send one byte. */
				codeBuf.put(0, (byte) (codeBuf.get(0) | mask));
				codeBuf.put(sp.textBuf.get(r));
			}
			else {
				/* Send position and length pair. Note match_length > THRESHOLD. */
				codeBuf.put((byte) sp.matchPosition);
				codeBuf.put((byte) //
				(/**/((sp.matchPosition >> 4) & 0xF0) //
					| (sp.matchLength - (THRESHOLD + 1))/**/) //
				);
			}
			if ((mask <<= 1) == 0) { /* Shift mask left one bit. */
				/* Send at most 8 units of code together */
				dst.write(codeBuf.array(), 0, codeBuf.position());
				codeBuf.clear();
				codeBuf.put((byte) 0);
				mask = 1;
			}
			lastMatchLength = sp.matchLength;
			for (i = 0; i < lastMatchLength; i++) {
				c = src.read();
				if (c == -1) {
					break;
				}
				sp.deleteNode(s); /* Delete old strings and */
				sp.textBuf.put(s, (byte) c); /* read new bytes */

				/**
				 * If the position is near the end of the buffer, extend the
				 * buffer to make string comparison easier.
				 */
				if (s < F - 1) {
					sp.textBuf.put(s + N, (byte) c);
				}

				/* Since this is a ring buffer, increment the position module N. */
				s = (s + 1) & (N - 1);
				r = (r + 1) & (N - 1);

				/* Register the string in text_buf[r..r+F-1] */
				sp.insertNode(r);
			}
			while (i++ < lastMatchLength) {
				sp.deleteNode(s);

				/* After the end of text, no need to read, */
				s = (s + 1) & (N - 1);
				r = (r + 1) & (N - 1);
				/* but buffer may not be empty. */
				if (--len != 0) {
					sp.insertNode(r);
				}
			}
		}
		while (len > 0); /* until length of string to be processed is zero */

		if (codeBuf.position() > 1) { /* Send remaining code. */
			dst.write(codeBuf.array(), 0, codeBuf.position());
		}

		dst.flush();
	}
}
