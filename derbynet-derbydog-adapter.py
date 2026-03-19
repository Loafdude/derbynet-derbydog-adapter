import asyncio
import aiohttp
import json
import struct
import xml.etree.ElementTree as ET
import argparse
import time
import logging

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("derby")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FRAME_HEADER     = b'\x1b\x10'
FRAME_TERMINATOR = b'\x0d'
MIN_FRAME        = 7   # header(2) + checksum(2) + length(2) + terminator(1)

# Seconds without a TE heartbeat before declaring the timer lost.
# TE heartbeats arrive every 20 seconds. 45s allows two full heartbeat
# intervals to be missed before declaring the connection dead, avoiding
# false positives from transient delays while still detecting power-loss promptly.
HEARTBEAT_TIMEOUT_DEFAULT = 45.0

# After registration completes, ignore RS frames for this many seconds.
# The firmware echoes RS as a handshake artifact before settling.
RS_GRACE_PERIOD = 3.0

# Human-readable command names for debug output.
COMMAND_NAMES = {
    b'RS': 'RS (Ready State)',
    b'RT': 'RT (Register Timer)',
    b'SR': 'SR (Set Rate)',
    b'ET': 'ET (Enable Timer)',
    b'TE': 'TE (Timer Echo / Ping)',
    b'RE': 'RE (Reset/Erase)',
    b'ER': 'ER (Echo Reset Confirm)',
    b'PE': 'PE (Program Event)',
    b'EP': 'EP (Event Programmed)',
    b'MA': 'MA (Match Result)',
    b'AM': 'AM (Ack Match)',
}


def _fmt_hex(data: bytes) -> str:
    return ' '.join(f'{b:02x}' for b in data)


def _cmd_name(cmd: bytes) -> str:
    return COMMAND_NAMES.get(cmd, f'?? ({cmd.hex()})')


# ---------------------------------------------------------------------------
# Frame accumulation buffer
# ---------------------------------------------------------------------------
class FrameBuffer:
    """Accumulates raw TCP bytes and yields complete, validated DerbyDog frames."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)

    def clear(self):
        self._buf.clear()

    def frames(self):
        """Yield the payload bytes of each complete, checksum-valid frame."""
        while True:
            idx = self._buf.find(FRAME_HEADER)
            if idx == -1:
                self._buf.clear()
                return
            if idx > 0:
                log.debug("Discarding %d pre-header bytes", idx)
                del self._buf[:idx]

            if len(self._buf) < MIN_FRAME:
                return

            payload_len = struct.unpack('>H', self._buf[4:6])[0]
            total_len   = 2 + 2 + 2 + payload_len + 1

            if len(self._buf) < total_len:
                return  # incomplete -- wait for more data

            frame = bytes(self._buf[:total_len])

            if frame[-1:] != FRAME_TERMINATOR:
                log.warning("Frame terminator mismatch -- resyncing")
                del self._buf[:2]
                continue

            declared = struct.unpack('>H', frame[2:4])[0]
            computed = 0
            for b in frame[4:4 + 2 + payload_len]:
                computed ^= b
            if declared != computed:
                log.warning(
                    "Frame checksum mismatch (declared=%04x computed=%04x) -- skipping",
                    declared, computed,
                )
                del self._buf[:2]
                continue

            payload = frame[6:6 + payload_len]
            del self._buf[:total_len]
            yield payload


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class DerbyMiddleware:
    def __init__(self, args):
        self.args  = args
        self.debug = getattr(args, 'debug', False)

        self.session = None
        self.reader  = None
        self.writer  = None

        clean_mac      = args.mac.replace(':', '').replace('-', '')
        mac_bytes      = bytes.fromhex(clean_mac)
        self.target_id = b'\x00' + mac_bytes[-3:]

        self.current_roundid     = None
        self.current_heat        = None
        self.timer_connected     = False
        self.hardware_ready_time = 0.0

        self._background_tasks: set[asyncio.Task] = set()
        self._frame_buffer = FrameBuffer()

        # Monotonic timestamp of the last TE heartbeat received.
        # Seeded at registration so the watchdog doesn't fire immediately.
        self._last_heartbeat: float = 0.0

        # Monotonic timestamp when registration completed.
        # RS frames within RS_GRACE_PERIOD of this are ignored as firmware artifacts.
        self._registered_at: float = 0.0

    # -----------------------------------------------------------------------
    # Debug helpers
    # -----------------------------------------------------------------------

    def _dbg_rx(self, payload: bytes):
        if not self.debug:
            return
        cmd = payload[3:5] if len(payload) >= 5 else b''
        log.info("[RX] %-28s | payload(%d): %s",
                 _cmd_name(cmd), len(payload), _fmt_hex(payload))

    def _dbg_tx(self, cmd: bytes, params: bytes):
        if not self.debug:
            return
        full = b'\x00\x00\x03' + cmd + params
        log.info("[TX] %-28s | payload(%d): %s",
                 _cmd_name(cmd), len(full), _fmt_hex(full))

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self):
        async with aiohttp.ClientSession() as self.session:
            await self.derbynet_login()

            # Announce ourselves to DerbyNet. It responds with the current
            # heat-ready state if a race is in progress, which process_derbynet_response
            # will pick up and use to arm the timer immediately.
            root = await self.derbynet_post({'action': 'timer-message', 'message': 'HELLO'})
            await self.process_derbynet_response(root)

            while True:
                await self._connect_with_retry()

                try:
                    await self.register_timer()
                    self._registered_at  = time.monotonic()
                    self._last_heartbeat = time.monotonic()
                    self.timer_connected = True

                    # Start all session coroutines together so timer_listen_loop
                    # is running before any RE/PE commands are sent to the timer.
                    # IDENTIFIED is sent on the first poll iteration (see
                    # derbynet_polling_loop) so DerbyNet's heat-ready response
                    # is processed while the listen loop is already consuming
                    # the timer's ER and EP acknowledgements concurrently.
                    await asyncio.gather(
                        self.derbynet_polling_loop(),
                        self.timer_listen_loop(),
                        self.heartbeat_watchdog(),
                    )

                except (ConnectionError, asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
                    log.error("Session lost: %s", e)
                    self.timer_connected = False
                    await self._close_writer()

                    # Clear the cached heat state so the duplicate-heat guard in
                    # process_derbynet_response does not skip re-arming on reconnect.
                    # DerbyNet will send the same roundid/heat in the IDENTIFIED
                    # response -- if we still hold those values the guard evaluates
                    # false and prepare_timer_for_heat never runs.
                    self.current_roundid = None
                    self.current_heat    = None

                    # MALFUNCTION with detectable=1 is the correct DerbyNet message
                    # when the timer connection is lost. DISCONNECTED is not a recognised
                    # message (DerbyNet returns 'notunderstood'). MALFUNCTION causes
                    # DerbyNet to mark the timer as offline and alert the operator.
                    log.info("Notifying DerbyNet of timer disconnect (MALFUNCTION)...")
                    await self.derbynet_post({
                        'action':     'timer-message',
                        'message':    'MALFUNCTION',
                        'detectable': '1',
                        'error':      'Timer connection lost',
                    })

                    # Send HELLO immediately so DerbyNet knows we are still running
                    # and will reconnect. It will respond with the current heat state
                    # once we come back up with IDENTIFIED.
                    root = await self.derbynet_post({'action': 'timer-message', 'message': 'HELLO'})
                    await self.process_derbynet_response(root)

    async def _connect_with_retry(self):
        """Open a TCP connection to the timer, retrying with exponential backoff.

        Backoff: 5s -> 10s -> 20s -> 40s -> 60s (cap).
        """
        delay   = 5.0
        attempt = 0
        while True:
            attempt += 1
            try:
                log.info(
                    "Connecting to timer at %s:%d (attempt %d)...",
                    self.args.timer_ip, self.args.timer_port, attempt,
                )
                await self.connect_timer()
                log.info("Timer connection established.")
                return
            except (OSError, asyncio.TimeoutError) as e:
                log.warning("Timer unreachable (%s). Retrying in %.0fs...", e, delay)
                await self._close_writer()
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)

    # -----------------------------------------------------------------------
    # Heartbeat watchdog
    # -----------------------------------------------------------------------

    async def heartbeat_watchdog(self):
        """Raise ConnectionError if TE heartbeats stop arriving.

        The timer sends TE periodically while registered. Silence longer than
        the timeout means the link is dead -- the TCP socket will not close
        on its own when the timer loses power abruptly.
        """
        timeout = self.args.heartbeat_timeout
        while self.timer_connected:
            await asyncio.sleep(5.0)
            elapsed = time.monotonic() - self._last_heartbeat
            if elapsed > timeout:
                raise ConnectionError(
                    f"Heartbeat timeout: no TE received for {elapsed:.1f}s "
                    f"(limit {timeout:.1f}s). Timer assumed lost."
                )

    # -----------------------------------------------------------------------
    # DerbyNet HTTP helpers
    # -----------------------------------------------------------------------

    async def derbynet_login(self):
        """POST credentials. role.login returns JSON, not XML."""
        payload = {
            'action':   'role.login',
            'name':     self.args.derbynet_user,
            'password': self.args.derbynet_pass,
        }
        url = f"{self.args.derbynet_url}/action.php"
        async with self.session.post(url, data=payload) as response:
            text = await response.text()

        try:
            data    = json.loads(text)
            outcome = data.get('outcome', {})
            summary = outcome.get('summary', '').lower()
            if summary != 'success':
                desc = outcome.get('description', outcome.get('code', 'unknown error'))
                raise RuntimeError(f"DerbyNet login rejected: {desc}")
            log.info("DerbyNet login accepted.")
            return
        except json.JSONDecodeError:
            pass

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise RuntimeError(
                f"DerbyNet login returned unparseable response: {text[:200]}"
            ) from exc

        failure = root.find('failure')
        if failure is not None:
            err = failure.text or failure.get('code', 'unknown error')
            raise RuntimeError(f"DerbyNet login rejected: {err}")

        log.info("DerbyNet login accepted.")

    async def derbynet_post(self, payload: dict, retry=True) -> ET.Element | None:
        url = f"{self.args.derbynet_url}/action.php"
        try:
            if self.debug:
                log.info("[DN TX] action=%-14s message=%s",
                         payload.get('action', '?'),
                         payload.get('message', payload))

            async with self.session.post(
                url, data=payload, timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                text = await response.text()

            if self.debug:
                log.info("[DN RX] %s", text.strip())

            try:
                root = ET.fromstring(text)
            except ET.ParseError:
                log.warning("XML parse error. Response: %s", text[:100])
                return None

            failure = root.find('failure')
            if failure is not None:
                err_msg = failure.text or ""
                if "not logged in" in err_msg.lower() or "login" in err_msg.lower():
                    if retry:
                        log.warning("Session desync -- re-authenticating...")
                        await self.derbynet_login()
                        return await self.derbynet_post(payload, retry=False)

            return root

        except aiohttp.ClientError as e:
            log.error("HTTP error during POST: %s", e)
            return None

    async def fetch_real_car_numbers(self) -> dict[int, int]:
        url = f"{self.args.derbynet_url}/action.php"
        try:
            async with self.session.get(
                url,
                params={'query': 'poll.coordinator'},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                content_type = response.headers.get('Content-Type', '')
                if 'json' not in content_type:
                    text = await response.text()
                    log.warning(
                        "poll.coordinator returned non-JSON (Content-Type: %s). "
                        "Falling back to lane index. Response: %s",
                        content_type, text[:120],
                    )
                    return {}
                data = await response.json()

            real_cars: dict[int, int] = {}
            for racer in data.get('racers', []):
                lane = int(racer.get('lane', 0))
                if lane == 0:
                    continue
                car_num_str = str(racer.get('carnumber', racer.get('car', lane)))
                clean       = ''.join(filter(str.isdigit, car_num_str))
                real_cars[lane] = int(clean) if clean else lane
            return real_cars

        except Exception as e:
            log.error("Error fetching real car numbers: %s", e)
            return {}

    # -----------------------------------------------------------------------
    # Timer TCP helpers
    # -----------------------------------------------------------------------

    async def connect_timer(self):
        """Open a TCP connection with a hard 10-second timeout."""
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.args.timer_ip, self.args.timer_port),
            timeout=10.0,
        )
        self._frame_buffer.clear()

    async def _close_writer(self):
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                log.debug("Error closing writer: %s", e)
            finally:
                self.writer = None

    def build_frame(self, command: bytes, params: bytes = b'') -> bytes:
        prefix       = b'\x00\x00\x03'
        payload      = prefix + command + params
        length_bytes = struct.pack('>H', len(payload))
        xor_sum = 0
        for b in (length_bytes + payload):
            xor_sum ^= b
        return b'\x1b\x10' + struct.pack('>H', xor_sum) + length_bytes + payload + b'\x0d'

    async def send_timer_raw(self, cmd: bytes, params: bytes = b''):
        if not self.writer:
            return
        self._dbg_tx(cmd, params)
        self.writer.write(self.build_frame(cmd, params))
        await self.writer.drain()

    async def register_timer(self):
        log.info("Sending registration handshake to timer...")
        await self.send_timer_raw(b'RT')
        await asyncio.sleep(0.25)
        await self.send_timer_raw(b'SR', b'\x01\x14')
        await asyncio.sleep(0.25)
        await self.send_timer_raw(b'ET')
        log.info("Timer registered.")

    # -----------------------------------------------------------------------
    # Hardware cooldown
    # -----------------------------------------------------------------------

    async def enforce_hardware_cooldown(self):
        now = time.time()
        if now < self.hardware_ready_time:
            wait_time = self.hardware_ready_time - now
            log.info("Hardware cooldown active. Waiting %.1fs...", wait_time)
            await asyncio.sleep(wait_time)

    # -----------------------------------------------------------------------
    # DerbyNet response dispatch
    # -----------------------------------------------------------------------

    async def process_derbynet_response(self, root: ET.Element):
        if root is None:
            return

        if root.find('failure') is not None:
            err_node = root.find('failure')
            err_msg  = err_node.text or err_node.get('code', 'Unknown Error')
            log.error("DerbyNet refused action: %s", err_msg)

        if root.find('abort') is not None:
            if self.current_heat is not None or self.current_roundid is not None:
                log.info("DerbyNet signaled abort. Clearing timer state...")
                self.current_roundid = None
                self.current_heat    = None
                await self.enforce_hardware_cooldown()
                await self.send_timer_raw(b'RE', self.target_id)
                await asyncio.sleep(0.25)

        heat_ready = root.find('heat-ready')
        if heat_ready is not None:
            new_round = heat_ready.get('roundid')
            new_heat  = heat_ready.get('heat')
            if new_round != self.current_roundid or new_heat != self.current_heat:
                self.current_roundid = new_round
                self.current_heat    = new_heat
                derbynet_mask = int(heat_ready.get('lane-mask'))
                log.info("Heat Ready: Round ID %s, Heat %s",
                         self.current_roundid, self.current_heat)
                await self.prepare_timer_for_heat(derbynet_mask)

    # -----------------------------------------------------------------------
    # Timer listen loop
    # -----------------------------------------------------------------------

    async def timer_listen_loop(self):
        """Read TCP frames from the timer and dispatch commands.

        Known commands and their correct handling:

        TE  Timer keep-alive ping. Reply ET immediately. Update heartbeat
            timestamp so the watchdog knows the link is alive.

        EP  Event Programmed. Timer confirms our PE (arm heat) was accepted.
            This is a one-way notification -- no reply is sent. Sending any
            reply causes the timer to echo EP again indefinitely.

        RS  Ready State. Timer has reset to Discovery state. Ignored within
            RS_GRACE_PERIOD seconds of registration (firmware handshake echo).
            After the grace period it means a genuine reset: raise
            ConnectionError so the session tears down and re-registers.

        MA  Match result. ACK with AM immediately, then process asynchronously.

        ER  Echo Reset Confirm. Response to our RE command. Log only.
        """
        while self.timer_connected:
            data = await self.reader.read(1024)
            if not data:
                raise ConnectionError("Hardware closed the TCP socket.")

            if self.debug:
                log.info("[RX RAW] %d bytes: %s", len(data), _fmt_hex(data))

            self._frame_buffer.feed(data)

            for payload in self._frame_buffer.frames():
                if len(payload) < 5:
                    log.warning("Payload too short for a command (%d bytes): %s",
                                len(payload), _fmt_hex(payload))
                    continue

                self._dbg_rx(payload)
                command = payload[3:5]

                if command == b'TE':
                    # Keep-alive ping. Reply ET and refresh the watchdog clock.
                    await self.send_timer_raw(b'ET')
                    self._last_heartbeat = time.monotonic()

                elif command == b'EP':
                    # Event Programmed -- one-way ACK from timer for our PE.
                    # Do NOT reply. Any reply causes an infinite EP echo loop.
                    log.info("Heat programming confirmed by timer (EP).")
                    # EP also proves the link is alive.
                    self._last_heartbeat = time.monotonic()

                elif command == b'RS':
                    # Ready State -- timer has reset to Discovery.
                    age = time.monotonic() - self._registered_at
                    if self._registered_at > 0 and age < RS_GRACE_PERIOD:
                        log.warning(
                            "RS received %.2fs after registration "
                            "(within %.1fs grace period) -- handshake artifact, ignoring.",
                            age, RS_GRACE_PERIOD,
                        )
                    else:
                        pkt_mac = payload[9:15] if len(payload) >= 15 else b''
                        raise ConnectionError(
                            f"RS received -- timer has reverted to Discovery state "
                            f"(MAC: {pkt_mac.hex(':') if pkt_mac else 'n/a'}). "
                            f"Tearing down session."
                        )

                elif command == b'MA':
                    # Match result. ACK immediately, process asynchronously.
                    await self.send_timer_raw(b'AM')
                    self._spawn_task(self.process_match_results(payload))

                elif command == b'ER':
                    log.info("Timer memory reset confirmed (ER).")

                else:
                    log.warning("Unhandled timer command %s -- payload: %s",
                                _cmd_name(command), _fmt_hex(payload))

    # -----------------------------------------------------------------------
    # Background task management
    # -----------------------------------------------------------------------

    def _spawn_task(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)

        def _on_done(t: asyncio.Task):
            self._background_tasks.discard(t)
            if not t.cancelled() and t.exception() is not None:
                log.error("Background task raised an exception", exc_info=t.exception())

        task.add_done_callback(_on_done)
        return task

    # -----------------------------------------------------------------------
    # Match result processing
    # -----------------------------------------------------------------------

    async def process_match_results(self, payload: bytes):
        """Parse an MA payload and post results to DerbyNet.

        MA payload layout:
          payload[0:3]   prefix   \\x00\\x00\\x03
          payload[3:5]   command  'MA'
          payload[5:11]  MA header (6 bytes of match/session metadata)
          payload[11:]   result blocks, 8 bytes each
        """
        roundid = self.current_roundid
        heat    = self.current_heat

        try:
            blocks = payload[11:]
            post_payload = {
                'action':  'timer-message',
                'message': 'FINISHED',
                'roundid': str(roundid),
                'heat':    str(heat),
            }

            for i in range(0, len(blocks), 8):
                block = blocks[i:i + 8]
                if len(block) < 8:
                    break
                lane       = block[0]
                place      = block[1]
                time_bytes = block[4:8]
                if time_bytes == b'\x00\xe4\xe1\xc0':
                    race_time = "9.999"
                else:
                    microseconds = struct.unpack('>I', time_bytes)[0]
                    race_time = f"{(microseconds / 1_000_000.0):.4f}"
                post_payload[f"lane{lane}"]  = race_time
                post_payload[f"place{lane}"] = str(place)

            log.info("Sending results to DerbyNet: %s", post_payload)
            response_xml = await self.derbynet_post(post_payload)

            if response_xml is not None and response_xml.find('success') is not None:
                self.hardware_ready_time = time.time() + self.args.cooldown
                log.info("Results accepted. Hardware locked for %.1fs.", self.args.cooldown)

            await self.process_derbynet_response(response_xml)

        except Exception as e:
            log.exception("Error parsing match results: %s", e)

    # -----------------------------------------------------------------------
    # DerbyNet polling loop
    # -----------------------------------------------------------------------

    async def derbynet_polling_loop(self):
        # Send IDENTIFIED on the very first poll so DerbyNet knows the timer
        # is registered and responds with heat-ready if a heat is waiting.
        # This runs inside gather() so timer_listen_loop is already active and
        # can consume the timer's ER/EP responses to RE/PE concurrently.
        # Subsequent polls use HEARTBEAT to keep DerbyNet's watchdog satisfied
        # and pick up any heat state changes.
        first_poll = True
        while self.timer_connected:
            message = 'IDENTIFIED' if first_poll else 'HEARTBEAT'
            first_poll = False
            if message == 'IDENTIFIED':
                log.info("Sending IDENTIFIED to DerbyNet -- requesting current heat state...")
            root = await self.derbynet_post({
                'action':  'timer-message',
                'message': message,
            })
            await self.process_derbynet_response(root)
            await asyncio.sleep(10.0)

    # -----------------------------------------------------------------------
    # Heat preparation
    # -----------------------------------------------------------------------

    async def prepare_timer_for_heat(self, derbynet_mask: int):
        await self.enforce_hardware_cooldown()

        log.info("Resetting track memory (RE)...")
        await self.send_timer_raw(b'RE', self.target_id)
        await asyncio.sleep(0.25)

        log.info("Fetching car numbers from DerbyNet (poll.coordinator)...")
        real_cars = await self.fetch_real_car_numbers()

        subtype     = b'\x02'
        match_bytes = struct.pack('>I', int(self.current_heat) if self.current_heat else 1)
        mask_bytes  = struct.pack('>H', derbynet_mask)

        car_ids = bytearray()
        for i in range(16):
            lane_number = i + 1
            if derbynet_mask & (1 << i):
                car_num = real_cars.get(lane_number, lane_number)
                car_ids.extend(struct.pack('>H', car_num))
            else:
                car_ids.extend(b'\x00\x00')

        params = self.target_id + subtype + match_bytes + mask_bytes + bytes(car_ids)
        log.info("Arming timer with mask %d (PE)...", derbynet_mask)
        await self.send_timer_raw(b'PE', params)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DerbyDog to DerbyNet Middleware")
    parser.add_argument(
        '--mac', required=True,
        help="Timer WiFi MAC address (e.g. b0:1f:81:00:01:08). Do NOT use the LAN MAC.",
    )
    parser.add_argument('--timer-ip',      required=True,          help="Timer IP address")
    parser.add_argument('--timer-port',    type=int, default=9001, help="TCP port (default: 9001)")
    parser.add_argument('--derbynet-url',  required=True,          help="http://localhost/derbynet")
    parser.add_argument('--derbynet-user', default="Timer",        help="DerbyNet username")
    parser.add_argument('--derbynet-pass', default="",             help="DerbyNet password")
    parser.add_argument(
        '--cooldown', type=float, default=10.0,
        help="Seconds to lock hardware before prepping the next heat (default: 10.0)",
    )
    parser.add_argument(
        '--heartbeat-timeout', type=float, default=HEARTBEAT_TIMEOUT_DEFAULT,
        help=f"Seconds without a TE before declaring the timer lost "
             f"(default: {HEARTBEAT_TIMEOUT_DEFAULT})",
    )
    parser.add_argument(
        '--debug', action='store_true',
        help="Log every raw packet sent and received as hex dumps.",
    )

    args = parser.parse_args()

    if args.debug:
        log.info("Debug mode enabled -- all packets will be logged.")

    try:
        asyncio.run(DerbyMiddleware(args).start())
    except KeyboardInterrupt:
        log.info("Shutting down middleware.")
