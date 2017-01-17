Samsung SHR-series DVR tools
============================

This repository contains some Python scripts for communicating with Samsung
SHR-series DVRs that speak the SmartViewer protocol.

These DVRs DO contain an RTSP server, however it's very poorly-implemented and
extremely sensitive to deviations in the messaging format, making it impossible
to view with an existing RTSP client. In my testing I have found the following
problems:

- RTSP server doesn't know what to do with OPTIONS. Clients like VLC will stall
  upon connection.
- RTSP server inserts spurious NULL bytes at the end of its replies.
- RTSP server expects `Authorization` header, but the value must be acquired
  from a Samsung-internal "DCP" service.
- RTSP server doesn't provide proper SDP in response to DESCRIBE.
- RTSP server deadlocks(!) the whole DVR(!!) unless SETUP requests provide the
  headers in a very particular order.
  (This happens even without authentication!!!)
- RTSP server doesn't properly \r\n\r\n-terminate a SETUP response.

Tools in this repository
------------------------

This repository provides 2 scripts:

- svtool.py talks to the SmartViewer DCP service to get an authorization token.
  In the future, it could be extended to support other aspects of the protocol,
  but currently it's just a shim to allow login
- rtsp_proxy.py sits between your RTSP client of choice (Live555, VLC, ...) and
  the DVR's RTSP server, and tries to translate the protocol just enough for a
  well-written RTSP client to connect successfully.

Caveats
-------

- Please set your network protocol in the DVR to UDP. TCP framing tends to
  work very poorly.

Supported DVRs
--------------

I'm not sure how many DVRs are supported here. I've only tested against the
SRD-1650DC. Strings from one of Samsung's DLLs suggest the following model
numbers follow this protocol as well:

- **SDE-series**: SDE-3001 SDE-3003 SDE-4001 SDE-4001V SDE-4002 SDE-4002V SDE-5001 SDE-5001V SDE-5002 SDE-5002V
- **SHR-series**: SHR-204X SHR-208X SHR-216X SHR-4081 SHR-4160 SHR-508X SHR-516X SHR-608X SHR-616X SHR-708X SHR-716X SHR-808X SHR-816X SHR-XXX
- **SRD-series**: SRD-161 SRD-161X SRD-163 SRD-163X SRD-1640 SRD-165 SRD-165X SRD-167 SRD-167X SRD-440 SRD-442 SRD-44X SRD-47 SRD-47X SRD-83 SRD-83X SRD-840 SRD-85 SRD-85X SRD-87 SRD-87X

Getting help
------------

I make no promises about my ability to provide support, but please provide
packet captures (tcpdump, Wireshark, ...) when reporting issues here on GitHub.

PSA
---

**Please keep your DVR devices off of the public internet!** Devices like DVRs,
IP cameras, and the like are notorious for having extremely poor security.
Malware threats are starting to target these kinds of devices exclusively,
and the upload bandwidth from these devices alone has been enough to mount
record-breaking cyberattacks against critical internet infrastructure.
**If you leave your device on the internet, bad people can and will get into it!!!**

I recommend installing a good software solution to watch your CCTV systems for
you instead of putting the CCTV systems on the internet directly. Expose it to
the internet if you must, but update often.
