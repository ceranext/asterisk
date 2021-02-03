# Support for UMTS Voice Calls via Direct IuUP
This branch is a POC that adds support for routing UMTS (3g) voice call RTP streams directly to/from Asterisk, via
the IuUP protocol, where the MGW acts as a transparent proxy. It is a patchy and temporary solution that is incorrect
by design and breaks the specs and **will not** work in any standard deployment. 
It is specifically tailored and tested on the following setup.
* RNC + BTS: **ip.access S60Z**, configured as UMTS Home NodeB.
* Core Network: **Osmocom** with **sip-connector**, with a few patches for **osmo-mgw** as well,
  which are located [here](https://github.com/ceranext/osmo-mgw/tree/up).

### Previous work
This patch is based on [Asterisk-AMR repo](https://github.com/ceranext/asterisk-amr), which adds a decent support for the RTP AMR codec ([RFC 4867](https://tools.ietf.org/html/rfc4867)) to Asterisk. 
For it to work, the peer must also speak this RFC, which is indeed the case in proper PBX-PBX links,
including the UMTS **Nb** interface (*MGW<--->PBX*).
**However**, UMTS voice calls don't use the RFC spec over the **Iu** interface  (*RNC<--->MGW*).
Instead, it introduces a whole new protocol layer above RTP, named **IuUP** (specifically SMpSDU version 1), 
which is described by [3GPP TS 25.415 (Release 99 Only!)](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=17324) and a few others mentioned below.
Thes specs are incompatible with the RFC spec, furthermore there's no SDP definition for using IuUP.
Therefore a proper UMTS-aware MGW is required to interconnect the two interfaces by translating between the 
3GPP and RFC specs:
```
                Iu                        Nb
(RNC) <---- IuUP/RTP ----> (MGW) <---- AMR/RTP ----> (PBX).
```       
Thus the above patch is insufficient when using **osmo-mgw**, which only bridges the RTP packets.

*Other essential 3GPP TS specs for this matter are: **25.414, 26.102, 26.103, 29.414**.*
### Solution
As mentioned above, the proper generic solution **should have** been in the MGW, and not at all in the PBX (Asterisk).
**Instead**, for simplicity of implementation of the POC, this patch **is** in Asterisk and works as follows:
The IuUP data packets are exchanged directly between the RNC and Asterisk, transparently passing through **osmo-mgw**.
Since **SIP/SDP** have no IuUP concept, the negotiation between osmo-mgw and Asterisk keeps on using 
RFC 4867, therefore breaking the spec and interoperability:
```
(RNC) <---- IuUP/RTP ----> (osmo-mgw) <---- IuUP/RTP disguised as AMR/RTP ----> (Asterisk)
```
* Only *IuUP Data* packets are passed through; The *IuUP Init* packets are handled correctly by osmo-mgw.

As mentioned above, there is currently no dynamic way (via SIP/SDP) to indicate which mode the AMR codec
should use for a particular session, so it is currently set globally for all (AMR) sessions, during compile time.
This only affects the narrowband variant of the codec, namely **AMR-NB ("AMR/8000")**.
When IuUP mode is enabled, the AMR-specific attributes received in the SDP are ignored.

### Building Asterisk
Regardless of this patch, the AMR codec requires the installation of OpenCORE AMR, for example in Debian/Ubuntu:
`apt install libopencore-amrnb-dev libopencore-amrwb-dev libvo-amrwbenc-dev`

The simplest way to enable IuUP mode is during configuration phase:
`./configure ... CFLAGS="-DAMR_RTP_SPEC_IUUP_INSTEAD_OF_RFC"`

The rest of the build process remains the same.

### Other Dependencies
As mentioned earlier, for a complete setup to work, a few subtle patches are also required in **osmo-mgw**,
which are located in the **UP** branch [here](https://github.com/ceranext/osmo-mgw/tree/up).

### Missing Materials
- Sample traces/logs

### Issues
- Didn't test long calls (>10 minutes) for any problems, such as time sync issues
- Due to us breaking the specs and using a standard AMR SDP even in IuUP mode, Wireshark 
  wrongly parses the MGW<->Asterisk RTP payloads as AMR
- Not sure if egress IuUP frame numbers are advanced correctly (See 3GPP TS 25.415 section 6.6.3.3).
  Ignored on ingress
- Didn't add sample IuUP payloads yet. Asterisk tests the sample payloads at init time and 
  fails in IuUP mode because the payloads are in RFC AMR format, but it doesn't seem to affect anything
- DTX seems to kinda work, but not tested correctly
- Didn't test CPU/memory performance or check for memory leaks

### Limitations
- Only supports the specific IuUP RFCI mapping used by S60Z default setup
- Only supports AMR-NB and only frame type 7 (12.2 kbps)
- Cannot use both IuUP and RFC modes in the same build
- Dynamic RTP payloads don't work properly on Osmocom side, so AMR-NB must use type 112 in both directions
- Cannot support rate update procedure/mode change requests
  But it's irrelevant here since we only support a single AMR frame type
- DTMF unsupported
- IuUP checksum is set to zero on egress (Ignored by S60Z) and ignored on ingress
- No support for IuUP PDU type 1
