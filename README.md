# DerbyDog to DerbyNet Async Middleware

A high-performance, asynchronous Python middleware bridge connecting a physical DerbyDog Pinewood Derby timer to the DerbyNet web-based race management system. 

This script maps DerbyNet's HTTP polling model to the DerbyDog's TCP/UDP push model. It natively handles track registration, persistent keep-alives, vacant lane spatial mapping, real car-number polling, and hardware cooldown queues to ensure flawlessly resilient race days.

## Features
* **Asynchronous I/O:** Uses `asyncio` and `aiohttp` to ensure the TCP hardware connection is never blocked by DerbyNet web server lag.
* **Smart Vacant Lanes:** Traces DerbyNet's active lane mask and injects spatial byte spacers into the track memory
* **Dashboard Hijacking:** Bypasses standard timer protocol limitations by seamlessly querying DerbyNet's internal API (`poll.coordinator`) to fetch and display real car numbers on the physical track display.
* **Hardware Cooldown Queue:** Pauses overlapping commands during rapid UI schedule changes (Aborts/Re-runs) to prevent UART buffer overruns on the timer's MCU.
* **Session Auto-Healing:** Automatically re-authenticates and recovers the `PHPSESSID` cookie if the DerbyNet PHP session expires mid-race.

## Requirements
* Python 3.13+
* `aiohttp` (`pip install aiohttp`)

## Usage

DerbyDog timer runs an open TCP port 9001 on both wifi and LAN interfaces. 
Ensure you use the WIFI mac address (NOT the LAN mac) on the command line regardless of which interface you use.
Start the middleware from the command line, passing your specific network and authentication parameters:

    python derby_middleware.py \
      --mac b0:1f:81:00:01:08 \
      --timer-ip 192.168.10.150 \
      --timer-port 9001 \
      --derbynet-url http://192.168.10.100/derbynet \
      --derbynet-user Timer \
      --derbynet-pass secret \
      --cooldown 10.0

### CLI Arguments
* `--mac`: **(Required)** The WIFI MAC address of the timer hardware. Do NOT use the LAN MAC.
* `--timer-ip`: **(Required)** The IP address of the DerbyDog timer on your local network.
* `--timer-port`: The TCP port for command traffic. Default is `9001`.
* `--derbynet-url`: **(Required)** The base URL to your DerbyNet installation.
* `--derbynet-user`: The DerbyNet timer role username. Default is `Timer`.
* `--derbynet-pass`: The password for the timer role. Default is empty.
* `--cooldown`: Seconds to lock the hardware queue before prepping the next heat. Default is `10.0`.

---

## Appendix A: DerbyDog Timer Protocol Specification v1.11

### 1. Transport Layer
The timer utilizes a USR-WIFI232-S module for wifi and a Freescale Kinetis K60 MCU.
* **UDP Port 8001:** Accepts messages on port 8001. Target IP and port are configured via http configuration page on lan interface 
* **TCP Port 9001:** No authentication. Same protocol as UDP

* DerbyDog timer does not volunteer information. You must register with the timer and trigger races via software for results to be published to the TCP/UDP port. Manually started races will NOT send race data.

### 2. Universal Frame Structure
All packets transmitted between the PC and the Timer strictly adhere to the following byte structure. Any deviation in length or checksum will result in the hardware silently dropping the packet.

| Index | Size | Description |
| :--- | :--- | :--- |
| `[0-1]` | 2 bytes | **Header:** Always `1b 10` (ESC DLE). |
| `[2-3]` | 2 bytes | **Checksum:** 16-bit big-endian unsigned integer. It is the bitwise XOR sum of all bytes starting from Index 4 up to (but not including) the Terminator. The upper byte is always `00`. |
| `[4-5]` | 2 bytes | **Payload Length:** 16-bit big-endian unsigned integer representing the total number of bytes from Index 6 to the end of the payload (excluding the Terminator). |
| `[6-8]` | 3 bytes | **Prefix:** Always `00 00 03`. |
| `[9-10]`| 2 bytes | **Command Code:** 2-character ASCII string (e.g., `50 45` for 'PE'). |
| `[11-N]`| Variable| **Parameters/Payload:** Specific to the command. |
| `[N+1]` | 1 byte | **Terminator:** Always `0d` (CR). |

**Checksum Algorithm Example:**
For a payload array P starting at the Length bytes (Index 4) and ending at the last parameter byte, Checksum = P[0] ^ P[1] ^ P[2] ... ^ P[n]. The result is packed as `>H`.

### 3. State Machine & Connection Lifecycle

**A. Discovery (Unregistered State)**
* When powered on, the timer continuously broadcasts an `RS` (Ready State) packet over UDP 8001 / TCP 9001.
* Command: `RS`.
* Timer Payload: `01 06 00 3f [6-byte MAC Address]`.
* Note: The timer will reject operational commands (`PE`, `RE`, `TS`) while in this state.

**B. Registration Handshake**
* The PC must claim the timer by sending three sequential commands. Delays of ~200ms between packets are recommended to prevent UART buffer overruns.
* PC sends `RT` (Ready Timer). Payload: None.
* PC sends `SR` (Set Ready). Payload: `01 14`.
* PC sends `ET` (Enable Timer). Payload: None.
* Result: The timer ceases the `RS` broadcast and enters the Armed/Listening state.

**C. Keep-Alive Heartbeat**
* Once registered, the timer will asynchronously push a ping to ensure the PC is still online.
* Timer sends `TE` (Timer Echo). Payload: `00 [6-byte MAC Address]`.
* PC MUST reply `ET` (Enable Timer) immediately. Payload: None.
* Failure to reply will result in the timer dropping the connection and reverting to the Discovery state.

### 4. Operational Commands
**Target ID Requirement:** Most active commands sent from the PC require the Target ID to be prefixed to the payload. For this hardware, the Target ID is `00 00 01 08` (derived from the MAC address b0 1f 81 00 01 08).

**Test Sensors (`TS` / `ST`)**
* Verifies optical sensor functionality.
* PC sends `TS`: Payload: `[Target ID] 01 02 03 04 05 06 07 08 09`.
* Timer replies `ST`: Payload mirrors the request with appended hardware state hex codes.

**Reset Track (`RE` / `ER`)**
* Clears the track's memory and disarms the gate.
* PC sends `RE`: Payload: `[Target ID]`.
* Timer replies `ER`: Payload: `00`.

### 5. Race Execution & Data Parsing

**Heat Prepare (`PE` / `EP`)**
* Arms the timer for a specific race configuration. The MCU expects a rigidly sized memory block.
* PC sends `PE`:
    * `[0-3]` Target ID (`00 00 01 08`).
    * `[4]` Subtype flag (`02`).
    * `[5-8]` Match ID (32-bit big-endian int).
    * `[9-10]` Active Lane Mask (16-bit int. e.g., 6 lanes = `00 3f`, 4 lanes = `00 0f`).
    * `[11-42]` Car ID Array. Exactly 32 bytes long. Populated with 16-bit integers mapping Car IDs to active ports. Any unused space in this 32-byte block MUST be padded with `00`.
* Timer replies `EP`: Acknowledges the track is armed.

**Match Results (`MA` / `AM`)**
* The track uses a push model. When the physical gate drops and cars finish, the timer asynchronously pushes the `MA` packet.
* Timer sends `MA`:
    * `[0]` Subtype (`02`).
    * `[1-4]` Match ID (Echoed from the `PE` packet).
    * `[5]` Separator (`00`).
    * `[6-N]` Lane Data Blocks: A series of contiguous 8-byte blocks.
* PC MUST reply `AM`: Acknowledges receipt of the results. Payload: None.

**Lane Data Block Parsing & Error Handling:**
* Each 8-byte block inside the `MA` payload is mapped as follows:
    * **Byte 0:** Physical Port ID (`01`, `02`, `03`...).
    * **Byte 1:** Place/Rank (`01` = 1st, `02` = 2nd).
    * **Bytes 2-3:** Car ID (Echoed from the `PE` configuration).
    * **Bytes 4-7:** Race Time (32-bit big-endian unsigned integer representing microseconds).
* **Handling DNFs (Did Not Finish):** If a car flies off the track, the MCU waits for a hardcoded 15-second timeout. The resulting lane block will have the Place byte set to `00`, and the Time bytes set to `00 e4 e1 c0` (~14,999,488 microseconds).
* **Handling Byes (Empty Lanes):** If a lane is masked out in the `PE` command (e.g., running a 4-car heat on a 6-lane track), the timer dynamically truncates the `MA` payload. It entirely omits the 8-byte data block for the inactive ports. The parser iterates through the payload by checking the remaining packet length rather than assuming a fixed 6-block array.
