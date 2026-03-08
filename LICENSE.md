HoneytrapAI Source Available License

Version 1.0, 2026



Copyright (c) 2026 Anthony Watts / HoneytrapAI

All rights reserved.



TERMS AND CONDITIONS



1\. DEFINITIONS



"Software" means the HoneytrapAI source code, documentation, and associated

files in this repository.



"Licensor" means Anthony Watts / HoneytrapAI.



"You" means the individual or entity exercising rights under this License.



"Commercial Use" means any use of the Software, in whole or in part, intended

for or directed toward commercial advantage or monetary compensation, including

but not limited to: selling the Software, bundling it into a paid product or

service, offering it as a hosted or cloud-based service, or redistributing

modified versions for commercial purposes.





2\. GRANT OF RIGHTS



Subject to the terms and conditions of this License, the Licensor grants You

a worldwide, royalty-free, non-exclusive, non-transferable license to:



&nbsp; a) Download, install, and run the Software for personal or home use;



&nbsp; b) Self-host the Software on hardware you own or control, for your own

&nbsp;    personal or internal non-commercial purposes;



&nbsp; c) Submit contributions (bug fixes, improvements, new features) back to the

&nbsp;    official HoneytrapAI repository, subject to the Licensor's contributor

&nbsp;    terms. By submitting a contribution, You assign to the Licensor all

&nbsp;    rights, title, and interest in that contribution, including the right

&nbsp;    to relicense it under any terms the Licensor chooses.





3\. RESTRICTIONS



You may not, without prior written permission from the Licensor:



&nbsp; a) Sell, license, sublicense, or otherwise transfer the Software or any

&nbsp;    derivative work to any third party for monetary compensation;



&nbsp; b) Bundle or incorporate the Software, in whole or in part, into any product

&nbsp;    or service that is sold, licensed, or otherwise made available for a fee;



&nbsp; c) Offer the Software or any derivative work as a hosted, cloud-based, or

&nbsp;    software-as-a-service offering to third parties;



&nbsp; d) Redistribute modified or unmodified copies of the Software for commercial

&nbsp;    purposes;



&nbsp; e) Remove or alter any copyright notices, license headers, or attribution

&nbsp;    statements in the Software.





4\. REDISTRIBUTION (NON-COMMERCIAL)



You may share unmodified copies of the Software for non-commercial purposes

provided that:



&nbsp; a) This License and all copyright notices are retained in full;



&nbsp; b) No fee is charged for the copy beyond reasonable media or distribution

&nbsp;    costs;



&nbsp; c) The recipient receives a copy of this License.





5\. THIRD-PARTY COMPONENTS



The Software is designed to operate alongside third-party components that are

licensed separately and are NOT covered by this License. Your rights and

obligations with respect to those components are governed solely by their

respective licenses.



The following third-party components may be installed or invoked by the

Software at runtime as independent processes. No source code or binaries from

these components are included in this repository, and no copyright claim is

made over them:



&nbsp; a) Maltrail (https://github.com/stamparm/maltrail)

&nbsp;    Copyright (c) 2014-2026 Maltrail developers

&nbsp;    Licensed under the MIT License.

&nbsp;    See: https://github.com/stamparm/maltrail/blob/master/LICENSE

&nbsp;    HoneytrapAI invokes Maltrail as a separate system process and does not

&nbsp;    link to, modify, or distribute its source code. The MIT License permits

&nbsp;    use and distribution with no copyleft restrictions provided the above

&nbsp;    copyright notice is retained.



&nbsp; b) AdGuard Home (https://github.com/AdguardTeam/AdGuardHome)

&nbsp;    Copyright (c) AdGuard Software Ltd. and contributors

&nbsp;    Licensed under the GNU General Public License v3.0 (GPL-3.0).

&nbsp;    See: https://www.gnu.org/licenses/gpl-3.0.html

&nbsp;    AdGuard Home is intentionally excluded from the shipped appliance image.

&nbsp;    It is downloaded directly from AdGuard's official GitHub repository

&nbsp;    during the first-run setup wizard, where the user accepts its GPL-3.0

&nbsp;    license terms before installation. HoneytrapAI communicates with AdGuard

&nbsp;    Home via its local HTTP API as a separate process and does not link to,

&nbsp;    modify, or distribute its source code or binaries.

&nbsp;    Note: The AdGuard EULA (adguard.com/en/eula.html) governs AdGuard's

&nbsp;    separate commercial products only and does not apply to AdGuard Home.



&nbsp; c) Linux kernel and Raspberry Pi OS system libraries

&nbsp;    Licensed under the GNU General Public License v2.0 (GPL-2.0) with the

&nbsp;    Linux Syscall Note, which explicitly permits user-space applications to

&nbsp;    use kernel system calls without triggering GPL copyleft obligations.

&nbsp;    HoneytrapAI is a user-space application and does not incorporate or

&nbsp;    modify kernel code.



The separation of HoneytrapAI from the above components as independent

processes means that the copyleft requirements of GPL-3.0 (AdGuard Home)

do not extend to the HoneytrapAI source code. Maltrail's MIT License imposes

no copyleft restrictions. If You distribute a complete system image or

appliance that includes these components, You must comply with their

respective licenses — see DISTRIBUTION.md for details.





6\. NO WARRANTY



THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR

IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE

LICENSOR BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN

ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION

WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.





7\. TERMINATION



Your rights under this License terminate automatically if You breach any of

its terms. Upon termination You must destroy all copies of the Software in

your possession.





8\. GOVERNING LAW



This License shall be governed by and construed in accordance with the laws

of the State of California, without regard to its conflict of law provisions.





9\. CONTACT



To request a commercial license or written permission for uses not covered

by this License, contact: support@honeytrap.ai

