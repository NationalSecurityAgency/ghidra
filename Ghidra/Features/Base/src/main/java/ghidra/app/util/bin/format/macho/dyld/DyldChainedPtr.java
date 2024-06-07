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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedPtr {

	public enum DyldChainType {
		DYLD_CHAINED_PTR_ARM64E(1),    // stride 8, unauth target is vmaddr
		DYLD_CHAINED_PTR_64(2),    // target is vmaddr
		DYLD_CHAINED_PTR_32(3),
		DYLD_CHAINED_PTR_32_CACHE(4),
		DYLD_CHAINED_PTR_32_FIRMWARE(5),
		DYLD_CHAINED_PTR_64_OFFSET(6),   // target is vm offset
		DYLD_CHAINED_PTR_ARM64E_KERNEL(7),   // stride 4, unauth target is vm offset
		DYLD_CHAINED_PTR_64_KERNEL_CACHE(8),
		DYLD_CHAINED_PTR_ARM64E_USERLAND(9),   // stride 8, unauth target is vm offset
		DYLD_CHAINED_PTR_ARM64E_FIRMWARE(10),   // stride 4, unauth target is vmaddr
		DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE(11),   // stride 1, x86_64 kernel caches
		DYLD_CHAINED_PTR_ARM64E_USERLAND24(12),   // stride 8, unauth target is vm offset, 24-bit bind
		DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE(13), // stride 8, regular/auth targets both vm offsets. Only A keys supported
		DYLD_CHAINED_PTR_TYPE_UNKNOWN(-1);

		private final int val;
		private final String name;

		private DyldChainType(int v) {
			val = v;
			name = this.name().substring("DYLD_CHAINED_".length());
		}

		public static DyldChainType lookupChainPtr(int val) {
			return switch (val) {
				case 1 -> DYLD_CHAINED_PTR_ARM64E;
				case 2 -> DYLD_CHAINED_PTR_64;
				case 3 -> DYLD_CHAINED_PTR_32;
				case 4 -> DYLD_CHAINED_PTR_32_CACHE;
				case 5 -> DYLD_CHAINED_PTR_32_FIRMWARE;
				case 6 -> DYLD_CHAINED_PTR_64_OFFSET;
				case 7 -> DYLD_CHAINED_PTR_ARM64E_KERNEL;
				case 8 -> DYLD_CHAINED_PTR_64_KERNEL_CACHE;
				case 9 -> DYLD_CHAINED_PTR_ARM64E_USERLAND;
				case 10 -> DYLD_CHAINED_PTR_ARM64E_FIRMWARE;
				case 11 -> DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE;
				case 12 -> DYLD_CHAINED_PTR_ARM64E_USERLAND24;
				case 13 -> DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE;
				default -> DYLD_CHAINED_PTR_TYPE_UNKNOWN;
			};
		}

		public int getValue() {
			return val;
		}

		public String getName() {
			return name;
		}
	}

	public static final int DYLD_CHAINED_PTR_START_NONE = 0xFFFF;
	public static final int DYLD_CHAINED_PTR_START_MULTI = 0x8000;
	public static final int DYLD_CHAINED_PTR_START_LAST = 0x8000;

	public static long getStride(DyldChainType ptrFormat) {
		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
			case DYLD_CHAINED_PTR_32:
			case DYLD_CHAINED_PTR_32_CACHE:
			case DYLD_CHAINED_PTR_32_FIRMWARE:
				yield 4;
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
				yield 8;
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			default:
				yield 1;
		};
	}

	public static int getSize(DyldChainType ptrFormat) {
		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_32:
			case DYLD_CHAINED_PTR_32_CACHE:
			case DYLD_CHAINED_PTR_32_FIRMWARE:
				yield 4;
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
			default:
				yield 8;
		};
	}

	public static long getChainValue(BinaryReader reader, long chainLoc, DyldChainType ptrFormat)
			throws IOException {
		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_32:
			case DYLD_CHAINED_PTR_32_CACHE:
			case DYLD_CHAINED_PTR_32_FIRMWARE:
				yield reader.readUnsignedInt(chainLoc);
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
				yield reader.readLong(chainLoc);
			default:
				yield 0;
		};
	}

	public static boolean isRelative(DyldChainType ptrFormat) {
		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
				yield true;
			default:
				yield false;
		};
	}

	public static boolean isBound(DyldChainType ptrFormat, long chainValue) {

		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
				yield ((chainValue >>> 62) & 1) != 0;
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
				yield ((chainValue >>> 63) & 1) != 0;
			case DYLD_CHAINED_PTR_32:
				yield ((chainValue >>> 31) & 1) != 0;
			default:
				yield false;
		};
	}

	public static boolean isAuthenticated(DyldChainType ptrFormat, long chainValue) {
		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_32:
			case DYLD_CHAINED_PTR_32_CACHE:
			case DYLD_CHAINED_PTR_32_FIRMWARE:
				yield false;
			default:
				yield ((chainValue >>> 63) & 1) != 0;
		};
	}

	public static long getTarget(DyldChainType ptrFormat, long chainValue) {

		if (isBound(ptrFormat, chainValue)) {
			return -1;
		}

		if (isAuthenticated(ptrFormat, chainValue)) {
			switch (ptrFormat) {
				case DYLD_CHAINED_PTR_ARM64E:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
				case DYLD_CHAINED_PTR_ARM64E_KERNEL:
					return chainValue & 0x000000FFFFFFFFL;
				case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
				case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
					return (chainValue & 0x3FFFFFFFL); // 30 bits
				case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
					return (chainValue & 0x3FFFFFFFFL); // 34 bits
				default:
					break;
			}
		}

		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
				long top8Bits = (chainValue >> 43) & 0xFFL;
				long bottom43Bits = chainValue & 0x000007FFFFFFFFFFL;
				// Hack! Top bits don't matter and are a pointer tag
				if (top8Bits == 0x80) {
					top8Bits = 0;
				}
				yield (top8Bits << 56) | bottom43Bits;

			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
				top8Bits = (chainValue >> 36) & 0xFFL;
				long bottom36Bits = chainValue & 0x00000FFFFFFFFFL;
				// Hack! Top bits don't matter and are a pointer tag
				if (top8Bits == 0x80) {
					top8Bits = 0;
				}
				yield (top8Bits << 56) | bottom36Bits;

			case DYLD_CHAINED_PTR_32:
				yield (chainValue & 0x3FFFFF); // 26 bits

			case DYLD_CHAINED_PTR_32_CACHE:
				yield (chainValue & 0x3FFFFFFF); // 30 bits

			case DYLD_CHAINED_PTR_32_FIRMWARE:
				yield (chainValue & 0x3FFFFF); // 26 bits

			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				yield (chainValue & 0x3FFFFFFF); // 30 bits

			case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
				yield (chainValue & 0x3FFFFFFFFL); // 34 bits

			default:
				yield 0;
		};
	}

	public static long getAddend(DyldChainType ptrFormat, long chainValue) {

		if (!isBound(ptrFormat, chainValue)) {
			return 0;
		}

		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
				long addend = (chainValue >>> 32) & 0x7FFFF;
				addend = ((addend & 0x40000) != 0 ? (addend | 0xFFFFFFFFFFFC0000L) : addend);
				yield addend;

			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
				yield (chainValue >>> 24) & 0xFF;

			case DYLD_CHAINED_PTR_32:
				yield (chainValue >>> 20) & 0x3F;  // 6 bits

			default:
				yield 0;
		};
	}

	public static long getOrdinal(DyldChainType ptrFormat, long chainValue) {

		if (!isBound(ptrFormat, chainValue)) {
			return -1;
		}

		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
				yield chainValue & 0xFFFF;

			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
				yield chainValue & 0xFFFFFF;

			case DYLD_CHAINED_PTR_32:
				yield chainValue & 0xFFFFF;

			default:
				yield -1;
		};
	}

	public static long getNext(DyldChainType ptrFormat, long chainValue) {
		return switch (ptrFormat) {
			case DYLD_CHAINED_PTR_ARM64E:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND:
			case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
			case DYLD_CHAINED_PTR_ARM64E_KERNEL:
				yield (chainValue >>> 51) & 0x7FF;   // 11-bits

			case DYLD_CHAINED_PTR_64:
			case DYLD_CHAINED_PTR_64_OFFSET:
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				yield (chainValue >>> 51) & 0xFFF;  // 12 bits

			case DYLD_CHAINED_PTR_32:
				yield (chainValue >>> 26) & 0x1F;  // 5 bits

			// Never bound
			case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
				yield 0;

			case DYLD_CHAINED_PTR_32_CACHE:
				yield (chainValue >>> 30) & 0x3;  // 2 bits

			case DYLD_CHAINED_PTR_32_FIRMWARE:
				yield (chainValue >>> 26) & 0x3F;  // 6 bits

			case DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:
				yield (chainValue >>> 52) & 0x7FF; // 11 bits

			default:
				yield 1;
		};
	}
}
