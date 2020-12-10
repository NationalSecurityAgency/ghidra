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
package ghidra.dbg.sctl.protocol.consts;

import ghidra.dbg.sctl.client.SctlExtension;

/**
 * See the SCTL documentation
 */
public enum Mkind {
	Reserved0,
	Rerror,
	Reserved2,
	Aevent,
	Tversion,
	Rversion,
	Tping,
	Rping,
	Tps,
	Rps,
	Tlaunch,
	Rlaunch,
	Tattach,
	Rattach,
	Tstat,
	Rstat,
	Tcont,
	Rcont,
	Tstop,
	Rstop,
	Tstep,
	Rstep,
	Tsnap,
	Rsnap,
	Tkill,
	Rkill,
	Tdetach,
	Rdetach,
	Ttrace,
	Rtrace,
	Tsettrap,
	Rsettrap,
	Tclrtrap,
	Rclrtrap,
	Tgetctx,
	Rgetctx,
	Tsetctx,
	Rsetctx,
	Tread,
	Rread,
	Twrite,
	Rwrite,
	Tlooksym,
	Rlooksym,
	Tenumsym,
	Renumsym,
	Tlooktype,
	Rlooktype,
	Tenumtype,
	Renumtype,
	Tlookaddr,
	Rlookaddr,
	Tenumloc,
	Renumloc,
	Tenumseg,
	Renumseg,
	Tnames,
	Rnames,
	Tunwind1,
	Runwind1,
	Tlooksrc,
	Rlooksrc,
	Tlookpc,
	Rlookpc,
	@SctlExtension("Execute a CLI command")
	Texec,
	@SctlExtension("CLI Command output")
	Rexec,
	Tenumctx,
	Renumctx,
	Tchoosectx,
	Rchoosectx,
	Tfocus,
	Rfocus,
	Tgetchildren,
	Rgetchildren,
	Tgetattributes,
	Rgetattributes,
}
