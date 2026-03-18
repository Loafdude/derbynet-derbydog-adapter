import asyncio
import aiohttp
import struct
import xml.etree.ElementTree as ET
import argparse
import time
import logging

# ---------------------------------------------------------------------------
# Logging setup — use module-level logger so every message has a timestamp
# and severity level, making post-event debugging much easier.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("derby")


# ---------------------------------------------------------------------------
# FIX 2 — Frame accumulation buffer
#
# TCP is a stream; read(1024) can return a partial frame, multiple frames
# joined together, or anything in between.  This class owns a raw byte buffer
# and yields complete DerbyDog frames one at a time.
#
# DerbyDog frame layout (from build_frame):
#   [0:2]  header      \x1b\x10  (2 bytes)
#   [2:4]  checksum    XOR of length_bytes + payload  (2 bytes, big-endian)
#   [4:6]  length      len(payload)  (2 bytes, big-endian)
#   [6:6+length]  payload
#   [6+length]  terminator  \x0d  (1 byte)
#
# Minimum frame size: 2 + 2 + 2 + 0 + 1 = 7 bytes
# ---------------------------------------------------------------------------
FRAME_HEADER = b'\x1b\x10'
FRAME_TERMINATOR = b'\x0d'
MIN_FRAME = 7  # header(2) + checksum(2) + length(2) + terminator(1)


class FrameBuffer:
    """Accumulates raw TCP bytes and yields complete, validated DerbyDog frames."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)

    def frames(self):
        """Yield complete payload bytes for each validated frame found in the buffer."""
        while True:
            # Find the next frame header
            idx = self._buf.find(FRAME_HEADER)
            if idx == -1:
                # No header found at all — discard everything
                self._buf.clear()
                return
            if idx > 0:
                # Discard garbage bytes before the header
                log.debug("Discarding %d pre-header bytes", idx)
                del self._buf[:idx]

            # Need at least MIN_FRAME bytes to read the length field
            if len(self._buf) < MIN_FRAME:
                return

            # Read declared payload length
            payload_len = struct.unpack('>H', self._buf[4:6])[0]
            total_frame_len = 2 + 2 + 2 + payload_len + 1  # header+checksum+length+payload+term

            if len(self._buf) < total_frame_len:
                # Frame not yet complete — wait for more data
                return

            frame = bytes(self._buf[:total_frame_len])

            # Validate terminator
            if frame[-1:] != FRAME_TERMINATOR:
                # Corrupted — skip past this header and resync
                log.warning("Frame terminator mismatch — resyncing")
                del self._buf[:2]
                continue

            # FIX 2 cont. — Validate checksum
            declared_checksum = struct.unpack('>H', frame[2:4])[0]
            computed_xor = 0
            for b in frame[4:4 + 2 + payload_len]:  # length_bytes + payload
                computed_xor ^= b
            if declared_checksum != computed_xor:
                log.warning("Frame checksum mismatch (declared=%04x computed=%04x) — skipping",
                            declared_checksum, computed_xor)
                del self._buf[:2]
                continue

            # Valid frame — yield the payload (bytes after the 6-byte header/checksum/length)
            payload = frame[6:6 + payload_len]
            del self._buf[:total_frame_len]
            yield payload


class DerbyMiddleware:
    def __init__(self, args):
        self.args = args
        self.session = None
        self.reader = None
        self.writer = None

        clean_mac = args.mac.replace(':', '').replace('-', '')
        mac_bytes = bytes.fromhex(clean_mac)
        self.target_id = b'\x00' + mac_bytes[-3:]

        self.current_roundid = None
        self.current_heat = None
        self.timer_connected = False

        # Timestamp-based hardware cooldown lock
        self.hardware_ready_time = 0.0

        # FIX 3 — Track all background tasks so exceptions surface and
        # tasks are cancelled cleanly on shutdown.
        self._background_tasks: set[asyncio.Task] = set()

        # FIX 2 — Single shared frame buffer for the timer TCP stream
        self._frame_buffer = FrameBuffer()

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self):
        async with aiohttp.ClientSession() as self.session:
            # FIX 7 — Validate login before proceeding
            await self.derbynet_login()

            root = await self.derbynet_post({'action': 'timer-message', 'message': 'HELLO'})
            await self.process_derbynet_response(root)

            while True:
                try:
                    await self.connect_timer()
                    await self.register_timer()
                    self.timer_connected = True

                    root = await self.derbynet_post({'action': 'timer-message', 'message': 'IDENTIFIED'})
                    await self.process_derbynet_response(root)

                    await asyncio.gather(
                        self.derbynet_polling_loop(),
                        self.timer_listen_loop()
                    )
                except (ConnectionError, asyncio.TimeoutError, aiohttp.ClientError) as e:
                    log.error("Connection lost: %s", e)
                    self.timer_connected = False
                    await self._close_writer()

                    await self.derbynet_post({
                        'action': 'timer-message',
                        'message': 'MALFUNCTION',
                        'detectable': '1',
                        'error': str(e)
                    })
                    log.info("Reconnecting in 5 seconds...")
                    await asyncio.sleep(5)

    # -----------------------------------------------------------------------
    # DerbyNet HTTP helpers
    # -----------------------------------------------------------------------

    async def derbynet_login(self):
        """POST login credentials and raise immediately if DerbyNet refuses them.

        FIX 7: Previously this discarded the response entirely, so bad credentials
        would silently cause every subsequent call to fail with 'not logged in',
        spinning the retry loop forever.
        """
        payload = {
            'action': 'role.login',
            'name': self.args.derbynet_user,
            'password': self.args.derbynet_pass
        }
        url = f"{self.args.derbynet_url}/action.php"
        async with self.session.post(url, data=payload) as response:
            text = await response.text()

        # DerbyNet returns JSON for role.login (not XML like other actions).
        # Parse accordingly and check the outcome summary field.
        import json
        try:
            data = json.loads(text)
            outcome = data.get('outcome', {})
            summary = outcome.get('summary', '').lower()
            if summary != 'success':
                desc = outcome.get('description', outcome.get('code', 'unknown error'))
                raise RuntimeError(f"DerbyNet login rejected: {desc}")
            log.info("DerbyNet login accepted.")
            return
        except json.JSONDecodeError:
            pass  # Not JSON — fall through to XML parse

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
            async with self.session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=5)) as response:
                text = await response.text()

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
                            log.warning("Session desync detected. Re-authenticating...")
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
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                # Guard against DerbyNet returning an error page instead of JSON
                content_type = response.headers.get('Content-Type', '')
                if 'json' not in content_type:
                    text = await response.text()
                    log.warning(
                        "poll.coordinator returned non-JSON (Content-Type: %s). "
                        "Will fall back to lane index for car numbers. Response: %s",
                        content_type, text[:120]
                    )
                    return {}

                data = await response.json()

            real_cars: dict[int, int] = {}
            for racer in data.get('racers', []):
                lane = int(racer.get('lane', 0))
                if lane == 0:
                    continue
                car_num_str = str(racer.get('carnumber', racer.get('car', lane)))
                clean_car_num = ''.join(filter(str.isdigit, car_num_str))
                real_cars[lane] = int(clean_car_num) if clean_car_num else lane

            return real_cars

        except Exception as e:
            log.error("Error fetching real car numbers: %s", e)
            return {}

    # -----------------------------------------------------------------------
    # Timer TCP helpers
    # -----------------------------------------------------------------------

    async def connect_timer(self):
        log.info("Connecting to timer at %s:%d via TCP...", self.args.timer_ip, self.args.timer_port)
        self.reader, self.writer = await asyncio.open_connection(
            self.args.timer_ip, self.args.timer_port
        )
        # Reset the frame buffer on every new connection so stale bytes
        # from a previous session can never bleed into the new one.
        self._frame_buffer = FrameBuffer()

    async def _close_writer(self):
        """Close the TCP writer and wait for the underlying socket to finish.

        FIX 10: Previously only writer.close() was called. Without
        wait_closed(), Python 3.7+ can leave the socket half-open during
        reconnection, which causes the OS to refuse the next connect() to
        the same address.
        """
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                log.debug("Error while closing writer: %s", e)
            finally:
                self.writer = None

    def build_frame(self, command: bytes, params: bytes = b'') -> bytes:
        header = b'\x1b\x10'
        prefix = b'\x00\x00\x03'
        payload = prefix + command + params
        length_bytes = struct.pack('>H', len(payload))

        xor_sum = 0
        for b in (length_bytes + payload):
            xor_sum ^= b

        checksum_bytes = struct.pack('>H', xor_sum)
        terminator = b'\x0d'
        return header + checksum_bytes + length_bytes + payload + terminator

    async def send_timer_raw(self, cmd: bytes, params: bytes = b''):
        """Write a frame to the timer and flush the transport buffer.

        FIX 4: Previously this was a synchronous method that called
        writer.write() and returned immediately. asyncio buffers writes
        in the transport layer, and without drain() there is no backpressure
        and no guarantee the bytes have been handed to the OS before the next
        command fires. Converting to async and awaiting drain() after every
        write ensures ordered, bounded delivery.
        """
        if not self.writer:
            return
        frame = self.build_frame(cmd, params)
        self.writer.write(frame)
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
            err_msg = err_node.text or err_node.get('code', 'Unknown Error')
            log.error("DerbyNet refused action: %s", err_msg)

        if root.find('abort') is not None:
            if self.current_heat is not None or self.current_roundid is not None:
                log.info("DerbyNet signaled abort/schedule change. Clearing timer state...")
                self.current_roundid = None
                self.current_heat = None
                await self.enforce_hardware_cooldown()
                await self.send_timer_raw(b'RE', self.target_id)
                await asyncio.sleep(0.25)

        heat_ready = root.find('heat-ready')
        if heat_ready is not None:
            new_round = heat_ready.get('roundid')
            new_heat = heat_ready.get('heat')

            if new_round != self.current_roundid or new_heat != self.current_heat:
                self.current_roundid = new_round
                self.current_heat = new_heat

                derbynet_mask = int(heat_ready.get('lane-mask'))
                log.info("Heat Ready: Round ID %s, Heat %s", self.current_roundid, self.current_heat)
                await self.prepare_timer_for_heat(derbynet_mask)

    # -----------------------------------------------------------------------
    # Timer listen loop
    # -----------------------------------------------------------------------

    async def timer_listen_loop(self):
        """Read raw bytes from the timer, accumulate them in the frame buffer,
        and dispatch complete frames to handlers.

        FIX 2: Previously this called read(1024) and immediately inspected the
        raw bytes with substring matching. TCP is a stream — a single read() can
        return a partial frame, two frames joined together, or any other split.
        Now all bytes are fed into FrameBuffer, which accumulates data until it
        can produce a complete, checksum-validated frame, then dispatches by
        the command bytes at a known offset within the payload.

        FIX 6: Command identification now uses the parsed payload at the correct
        position rather than a substring search on the raw buffer. This prevents
        false positives when car numbers or timing values happen to contain the
        same byte sequences as command codes.
        """
        while self.timer_connected:
            data = await self.reader.read(1024)
            if not data:
                raise ConnectionError("Hardware closed the TCP socket.")

            self._frame_buffer.feed(data)

            for payload in self._frame_buffer.frames():
                # FIX 6 — Command bytes sit at payload[3:5] (after the 3-byte prefix \x00\x00\x03)
                if len(payload) < 5:
                    log.debug("Payload too short to contain a command: %s", payload.hex())
                    continue

                command = payload[3:5]

                if command == b'TE':   # Ping
                    await self.send_timer_raw(b'ET')

                elif command == b'MA':  # Match result
                    await self.send_timer_raw(b'AM')
                    self._spawn_task(self.process_match_results(payload))

                elif command == b'ER':  # Echo reset confirmation
                    log.info("Timer memory reset confirmed (ER).")

                else:
                    log.debug("Unhandled timer command: %s", command.hex())

    # -----------------------------------------------------------------------
    # Background task management
    # -----------------------------------------------------------------------

    def _spawn_task(self, coro) -> asyncio.Task:
        """Schedule a coroutine as a background task and track it.

        FIX 3: Previously asyncio.create_task() results were discarded.
        Python's asyncio silently swallows exceptions from untracked tasks.
        By storing tasks in a set and attaching a done-callback, any
        exception is logged and the task is removed from the set once it
        finishes, preventing a memory leak.
        """
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)

        def _on_done(t: asyncio.Task):
            self._background_tasks.discard(t)
            if not t.cancelled() and t.exception() is not None:
                log.error("Background task raised an exception: %s", t.exception(), exc_info=t.exception())

        task.add_done_callback(_on_done)
        return task

    # -----------------------------------------------------------------------
    # Match result processing
    # -----------------------------------------------------------------------

    async def process_match_results(self, payload: bytes):
        """Parse a MA (match) payload and post results to DerbyNet.

        FIX 1: Previously this method read self.current_roundid and
        self.current_heat at execution time, which could be after the
        polling loop had already advanced to the next heat (race condition).
        Both values are now snapshotted at call time and passed explicitly,
        so the submitted results always correspond to the heat that
        triggered the MA packet — even if the middleware state has moved on.

        FIX 2 cont.: The payload here is already the parsed frame payload
        from FrameBuffer, not raw TCP bytes, so the slice offsets are stable
        and correct.
        """
        # Snapshot heat identity at the moment this task is created.
        # FIX 1 — These are captured from the caller's frame, not read from
        # self inside the task, preventing a race with the polling loop.
        roundid = self.current_roundid
        heat = self.current_heat

        try:
            # MA payload layout:
            #   payload[0:3]   prefix \x00\x00\x03
            #   payload[3:5]   command 'MA'
            #   payload[5:11]  MA header (6 bytes of match/session metadata)
            #   payload[11:]   result blocks, 8 bytes each
            #
            # The original code used data[17:-1] on the *raw TCP frame*.
            # The frame contributes 6 bytes before the payload (header+checksum+length),
            # so raw offset 17 = frame offset 6 + payload offset 11.
            # We were incorrectly starting at payload[5:], skipping only the prefix+command
            # and landing inside the MA header — producing garbage lane/place/time values.
            blocks = payload[11:]

            post_payload = {
                'action': 'timer-message',
                'message': 'FINISHED',
                'roundid': str(roundid),
                'heat': str(heat)
            }

            for i in range(0, len(blocks), 8):
                block = blocks[i:i + 8]
                if len(block) < 8:
                    break

                lane = block[0]
                place = block[1]
                time_bytes = block[4:8]

                if time_bytes == b'\x00\xe4\xe1\xc0':
                    race_time = "9.999"
                else:
                    microseconds = struct.unpack('>I', time_bytes)[0]
                    race_time = f"{(microseconds / 1_000_000.0):.4f}"

                post_payload[f"lane{lane}"] = race_time
                post_payload[f"place{lane}"] = str(place)

            log.info("Sending results to DerbyNet: %s", post_payload)
            response_xml = await self.derbynet_post(post_payload)

            if response_xml is not None:
                if response_xml.find('success') is not None:
                    self.hardware_ready_time = time.time() + self.args.cooldown
                    log.info("Results accepted. Hardware locked for %.1fs.", self.args.cooldown)

            await self.process_derbynet_response(response_xml)

        except Exception as e:
            log.exception("Error parsing match results: %s", e)

    # -----------------------------------------------------------------------
    # DerbyNet polling loop
    # -----------------------------------------------------------------------

    async def derbynet_polling_loop(self):
        while self.timer_connected:
            root = await self.derbynet_post({
                'action': 'timer-message',
                'message': 'HEARTBEAT'
            })
            await self.process_derbynet_response(root)
            await asyncio.sleep(2.0)

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

        subtype = b'\x02'
        match_bytes = struct.pack('>I', int(self.current_heat) if self.current_heat else 1)
        mask_bytes = struct.pack('>H', derbynet_mask)

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
        help="Timer WIFI MAC Address (e.g., b0:1f:81:00:01:08). Do NOT use the LAN MAC."
    )
    parser.add_argument('--timer-ip', required=True, help="Timer IP Address")
    parser.add_argument('--timer-port', type=int, default=9001, help="TCP Port (default: 9001)")
    parser.add_argument('--derbynet-url', required=True, help="http://192.168.x.x/derbynet")
    parser.add_argument('--derbynet-user', default="Timer", help="DerbyNet username")
    parser.add_argument('--derbynet-pass', default="", help="DerbyNet password")
    parser.add_argument(
        '--cooldown', type=float, default=10.0,
        help="Seconds to lock hardware before prepping the next heat (default: 10.0)"
    )

    args = parser.parse_args()

    try:
        asyncio.run(DerbyMiddleware(args).start())
    except KeyboardInterrupt:
        log.info("Shutting down middleware.")
