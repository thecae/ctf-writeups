---
description: Cracking a GPS location based off Wi-Fi availability nearby
---

# \[Amateurs '23] Screenshot Guesser

## Distribution

We were given a screenshot containing a few different local Wi-Fi networks and their respective connection distances:

<div align="center">

<img src="../.gitbook/assets/ScreenshotGuesser-screenshot.png" alt="Screenshot provided">

</div>

## Solution

The only noticeable network that we have here is the Primavera Foundation. I quickly Google'd this one and found that this foundation is in Tucson, Arizona. There are four major locations on the map.

I then happened to stumble across a site called [WiGLE](https://wigle.net/), a database of known Wi-Fi networks that's scannable by SSID. Bingo. I quickly realized that this site was less than easy to use and that it doesn't really ever point out where the network is, and you have to find it.

To get started, I tried searching for the Primavera Foundation network. I got a few more than four hits, which was shocking. I then started to scan for other networks and plotted down the locations I found in Google My Maps. After scanning for tiny purple dots on a map for plenty of time, I got to a valuable location: _I-10 x Speedway Blvd_.

I had to carefully place this location on the map because of the strengths of the Wi-Fi connection. Thankfully, from the Python script running on the remote port, we see that I just need to be in $$0.001$$ degrees (about $$100$$ meters) of the right place. I ended up choosing the coordinates `(32.2366, -110.98384)`.

We need to package this up and send it off to the remote host to get the flag.

{% code title="solve.py" lineNumbers="true" %}
```python
from pwn import *
import subprocess

r = remote('amt.rs', 31450)

check = r.recvline().decode().strip().split(' ')[-1]
ps = subprocess.Popen(f'curl -fsSL https://pwn.red/pow | sh -s {check}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
work = ps.communicate()[0]
r.send(work)

coords = '32.2366, -110.98384'.encode()
r.sendline(coords)

r.interactive()
```
{% endcode %}
